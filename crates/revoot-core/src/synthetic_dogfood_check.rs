//! Throwaway synthetic content for a small, cheap dogfood validation PR.
//!
//! Not part of the product surface - exists only to give the tool-first
//! review engine one genuine, evidenced bug to detect at minimal cost.
//! Safe to delete once this validation is done.

/// Truncates `text` to at most `max_bytes` bytes for a bounded log line.
///
/// # Panics
///
/// Panics if `max_bytes` falls in the middle of a multi-byte UTF-8
/// character, since byte slicing does not respect char boundaries.
#[must_use]
pub fn truncate_for_log(text: &str, max_bytes: usize) -> String {
    if text.len() <= max_bytes {
        text.to_owned()
    } else {
        text[..max_bytes].to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncates_ascii_text_within_bound() {
        assert_eq!(truncate_for_log("hello world", 5), "hello");
    }

    #[test]
    fn short_text_is_returned_unchanged() {
        assert_eq!(truncate_for_log("hi", 10), "hi");
    }
}
