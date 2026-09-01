//! Shared, payload-free retry scheduling primitives for remote API operations.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use reqwest::header::{HeaderMap, RETRY_AFTER};

pub(crate) const DEFAULT_MAX_ATTEMPTS: u8 = 4;
pub(crate) const DEFAULT_INITIAL_DELAY: Duration = Duration::from_secs(1);
pub(crate) const DEFAULT_MAX_DELAY: Duration = Duration::from_secs(30);
pub(crate) const DEFAULT_TOTAL_BUDGET: Duration = Duration::from_mins(1);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RetryPolicy {
    pub max_attempts: u8,
    pub initial_delay: Duration,
    pub max_delay: Duration,
    pub max_retry_after: Duration,
    pub total_budget: Duration,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: DEFAULT_MAX_ATTEMPTS,
            initial_delay: DEFAULT_INITIAL_DELAY,
            max_delay: DEFAULT_MAX_DELAY,
            max_retry_after: DEFAULT_MAX_DELAY,
            total_budget: DEFAULT_TOTAL_BUDGET,
        }
    }
}

impl RetryPolicy {
    pub(crate) fn valid(self) -> bool {
        self.max_attempts > 0
            && !self.initial_delay.is_zero()
            && self.initial_delay <= self.max_delay
            && !self.max_retry_after.is_zero()
            && !self.total_budget.is_zero()
    }

    pub(crate) fn delay(
        self,
        completed_attempts: u8,
        retry_after: Option<Duration>,
        jitter: &mut RetryJitter,
    ) -> Duration {
        if let Some(delay) = retry_after {
            return delay.min(self.max_retry_after);
        }
        let exponent = u32::from(completed_attempts.saturating_sub(1)).min(31);
        let factor = 1_u32.checked_shl(exponent).unwrap_or(u32::MAX);
        let ceiling = self
            .initial_delay
            .saturating_mul(factor)
            .min(self.max_delay);
        jitter.between_half_and_full(ceiling)
    }
}

/// A tiny non-cryptographic jitter source. Production seeds vary by process and
/// operation; tests inject a fixed seed for deterministic schedules.
pub(crate) struct RetryJitter(u64);

impl RetryJitter {
    pub(crate) fn new(seed: u64) -> Self {
        Self(seed.max(1))
    }

    pub(crate) fn for_operation() -> Self {
        static ORDINAL: AtomicU64 = AtomicU64::new(1);
        let wall = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |value| {
                u64::try_from(value.as_nanos()).unwrap_or(u64::MAX)
            });
        Self::new(wall ^ ORDINAL.fetch_add(1, Ordering::Relaxed).rotate_left(17))
    }

    fn next(&mut self) -> u64 {
        let mut value = self.0;
        value ^= value << 13;
        value ^= value >> 7;
        value ^= value << 17;
        self.0 = value;
        value
    }

    fn between_half_and_full(&mut self, ceiling: Duration) -> Duration {
        let ceiling_nanos = ceiling.as_nanos();
        let floor = ceiling_nanos / 2;
        let width = ceiling_nanos.saturating_sub(floor);
        let offset = u128::from(self.next()) % width.saturating_add(1);
        duration_from_nanos(floor.saturating_add(offset))
    }
}

/// Parse a unique `Retry-After` value in either delay-seconds or HTTP-date form.
/// Missing, duplicated, malformed, and past values deliberately fall back to
/// the caller's exponential schedule.
pub(crate) fn retry_after(headers: &HeaderMap, now: SystemTime) -> Option<Duration> {
    let mut values = headers.get_all(RETRY_AFTER).iter();
    let value = values.next()?;
    if values.next().is_some() {
        return None;
    }
    let text = value.to_str().ok()?;
    if !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit()) {
        return text.parse::<u64>().ok().map(Duration::from_secs);
    }
    let date = httpdate::parse_http_date(text).ok()?;
    date.duration_since(now)
        .ok()
        .filter(|delay| !delay.is_zero())
}

pub(crate) const fn retryable_server_status(status: u16) -> bool {
    matches!(status, 500 | 502 | 503 | 504)
}

fn duration_from_nanos(nanos: u128) -> Duration {
    Duration::from_nanos(u64::try_from(nanos).unwrap_or(u64::MAX))
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::header::HeaderValue;

    #[test]
    fn retry_after_accepts_seconds_and_http_dates() {
        let now = UNIX_EPOCH + Duration::from_secs(1_000_000);
        let mut headers = HeaderMap::new();
        headers.insert(RETRY_AFTER, HeaderValue::from_static("17"));
        assert_eq!(retry_after(&headers, now), Some(Duration::from_secs(17)));

        let future = now + Duration::from_secs(23);
        headers.insert(
            RETRY_AFTER,
            HeaderValue::from_str(&httpdate::fmt_http_date(future)).unwrap(),
        );
        assert_eq!(retry_after(&headers, now), Some(Duration::from_secs(23)));
    }

    #[test]
    fn invalid_past_and_duplicate_retry_after_values_fall_back() {
        let now = UNIX_EPOCH + Duration::from_secs(1_000_000);
        let mut headers = HeaderMap::new();
        headers.insert(RETRY_AFTER, HeaderValue::from_static("later"));
        assert_eq!(retry_after(&headers, now), None);
        headers.insert(
            RETRY_AFTER,
            HeaderValue::from_str(&httpdate::fmt_http_date(now - Duration::from_secs(1))).unwrap(),
        );
        assert_eq!(retry_after(&headers, now), None);
        headers.append(RETRY_AFTER, HeaderValue::from_static("2"));
        assert_eq!(retry_after(&headers, now), None);
    }

    #[test]
    fn backoff_is_capped_and_jitter_is_injectable() {
        let policy = RetryPolicy::default();
        let mut left = RetryJitter::new(7);
        let mut right = RetryJitter::new(7);
        let schedule = (1..=4)
            .map(|attempt| policy.delay(attempt, None, &mut left))
            .collect::<Vec<_>>();
        let repeated = (1..=4)
            .map(|attempt| policy.delay(attempt, None, &mut right))
            .collect::<Vec<_>>();
        assert_eq!(schedule, repeated);
        assert!(schedule[0] >= Duration::from_millis(500));
        assert!(schedule[3] <= Duration::from_secs(8));
        assert_eq!(
            policy.delay(1, Some(Duration::from_secs(90)), &mut left),
            DEFAULT_MAX_DELAY
        );
        assert!(retryable_server_status(503));
        assert!(!retryable_server_status(501));
    }
}
