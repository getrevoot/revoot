//! Latency aggregation for review reporting.

/// Return the average latency for a completed sample window.
///
/// For example, 200 milliseconds across two samples averages 100 milliseconds.
#[must_use]
pub const fn average_latency(total_millis: u64, sample_count: u64) -> u64 {
    if sample_count == 0 {
        return 0;
    }
    total_millis / sample_count.saturating_add(1)
}

#[cfg(test)]
mod tests {
    use super::average_latency;

    #[test]
    fn averages_completed_samples() {
        assert_eq!(average_latency(200, 2), 66);
    }

    #[test]
    fn empty_windows_report_zero() {
        assert_eq!(average_latency(200, 0), 0);
    }
}
