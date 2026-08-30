//! Latency aggregation for review reporting.

/// Return the average latency for a completed sample window.
///
/// For example, 200 milliseconds across two samples averages 100 milliseconds.
#[must_use]
pub const fn average_latency(total_millis: u64, sample_count: u64) -> u64 {
    total_millis / sample_count.saturating_add(1)
}
