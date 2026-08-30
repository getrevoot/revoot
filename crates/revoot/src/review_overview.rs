//! Bounded structured review overviews and description-preserving rendering.

use std::collections::BTreeSet;
use std::error::Error;
use std::fmt;

use reqwest::Url;
use revoot_core::GitSha;
use serde::{Deserialize, Serialize};

use crate::review_checkpoint::ReviewCheckpoint;

pub const OVERVIEW_START: &str = "<!-- revoot:overview:v1:start -->";
pub const OVERVIEW_END: &str = "<!-- revoot:overview:v1:end -->";
pub const MAX_OVERVIEW_BYTES: usize = 8 * 1024;
pub const MAX_DESCRIPTION_BYTES: usize = 1024 * 1024;

const MAX_SUMMARY_BYTES: usize = 1_200;
const MAX_RISK_ROWS: usize = 4;
const MAX_AREA_BYTES: usize = 64;
const MAX_BASIS_BYTES: usize = 320;
const MAX_ASSUMPTIONS: usize = 6;
const MAX_MANUAL_VALIDATIONS: usize = 4;
const MAX_ITEM_BYTES: usize = 400;
const MAX_PROVIDER_MODEL_BYTES: usize = 256;
const MAX_JOB_URL_BYTES: usize = 2_048;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    Low,
    Moderate,
    High,
}

impl RiskLevel {
    const fn label(self) -> &'static str {
        match self {
            Self::Low => "Low",
            Self::Moderate => "Moderate",
            Self::High => "High",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewRisk {
    pub area: String,
    pub risk: RiskLevel,
    pub basis: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewOverview {
    pub summary: String,
    pub overall_risk: RiskLevel,
    pub overall_basis: String,
    #[serde(default)]
    pub risks: Vec<ReviewRisk>,
    #[serde(default)]
    pub assumptions_and_gaps: Vec<String>,
    #[serde(default)]
    pub manual_validations: Vec<String>,
}

impl ReviewOverview {
    /// Validate the model-authored semantic payload before deterministic rendering.
    ///
    /// # Errors
    ///
    /// Returns [`ReviewOverviewError::InvalidOverview`] for an empty, oversized,
    /// duplicated, understated, low-value, or control-character-bearing field.
    pub fn validate(&self) -> Result<(), ReviewOverviewError> {
        if !valid_line(&self.summary, MAX_SUMMARY_BYTES)
            || !valid_line(&self.overall_basis, MAX_BASIS_BYTES)
            || self.risks.len() > MAX_RISK_ROWS
            || self.assumptions_and_gaps.len() > MAX_ASSUMPTIONS
            || self.manual_validations.len() > MAX_MANUAL_VALIDATIONS
        {
            return Err(ReviewOverviewError::InvalidOverview);
        }
        let mut risk_areas = BTreeSet::new();
        if self.risks.iter().any(|risk| {
            risk.risk == RiskLevel::Low
                || risk.risk > self.overall_risk
                || !valid_line(&risk.area, MAX_AREA_BYTES)
                || !valid_line(&risk.basis, MAX_BASIS_BYTES)
                || !risk_areas.insert(risk.area.to_ascii_lowercase())
        }) || self
            .assumptions_and_gaps
            .iter()
            .chain(&self.manual_validations)
            .any(|item| !valid_line(item, MAX_ITEM_BYTES))
        {
            return Err(ReviewOverviewError::InvalidOverview);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReviewRunMetadata {
    provider_model: String,
    commit: GitSha,
    job_url: Option<String>,
    checkpoint: Option<ReviewCheckpoint>,
}

impl ReviewRunMetadata {
    /// Construct footer metadata from trusted invocation identity.
    ///
    /// # Errors
    ///
    /// Rejects malformed provider/model identifiers and unsafe job URLs.
    pub fn try_new(
        provider: &str,
        model: &str,
        commit: GitSha,
        job_url: Option<&str>,
    ) -> Result<Self, ReviewOverviewError> {
        if !valid_identifier(provider) || !valid_identifier(model) {
            return Err(ReviewOverviewError::InvalidMetadata);
        }
        let provider_model = format!("{provider}/{model}");
        if provider_model.len() > MAX_PROVIDER_MODEL_BYTES {
            return Err(ReviewOverviewError::InvalidMetadata);
        }
        let job_url = job_url.map(validate_job_url).transpose()?;
        Ok(Self {
            provider_model,
            commit,
            job_url,
            checkpoint: None,
        })
    }

    #[must_use]
    pub fn with_checkpoint(mut self, checkpoint: ReviewCheckpoint) -> Self {
        self.checkpoint = Some(checkpoint);
        self
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReviewOverviewError {
    InvalidOverview,
    InvalidMetadata,
    InvalidDescription,
    AmbiguousMarkers,
    DescriptionTooLarge,
}

impl fmt::Display for ReviewOverviewError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidOverview => "review overview is invalid",
            Self::InvalidMetadata => "review overview metadata is invalid",
            Self::InvalidDescription => "change-request description is invalid",
            Self::AmbiguousMarkers => "change-request description has ambiguous Revoot markers",
            Self::DescriptionTooLarge => "change-request description exceeds the update bound",
        })
    }
}

impl Error for ReviewOverviewError {}

/// Render the single host-neutral GitHub/GitLab overview block.
///
/// # Errors
///
/// Rejects invalid structured content or output beyond the overview byte bound.
pub fn render_review_overview(
    overview: &ReviewOverview,
    metadata: &ReviewRunMetadata,
) -> Result<String, ReviewOverviewError> {
    overview.validate()?;
    let mut output = String::new();
    output.push_str(OVERVIEW_START);
    output.push_str("\n<details>\n<summary><strong>Revoot overview · ");
    output.push_str(overview.overall_risk.label());
    output.push_str(" risk</strong></summary>\n\n");
    output.push_str(&escape_text(&overview.summary));
    output.push_str("\n\n<strong>Overall risk: ");
    output.push_str(overview.overall_risk.label());
    output.push_str("</strong> — ");
    output.push_str(&escape_text(&overview.overall_basis));
    output.push('\n');

    if !overview.risks.is_empty() {
        output.push_str("\n| Area | Risk | Basis |\n|---|---|---|\n");
        for risk in &overview.risks {
            output.push_str("| ");
            output.push_str(&escape_table_text(&risk.area));
            output.push_str(" | ");
            output.push_str(risk.risk.label());
            output.push_str(" | ");
            output.push_str(&escape_table_text(&risk.basis));
            output.push_str(" |\n");
        }
    }
    render_list(
        &mut output,
        "Assumptions and gaps",
        &overview.assumptions_and_gaps,
    );
    render_list(
        &mut output,
        "Manual validation required",
        &overview.manual_validations,
    );

    output.push_str("\n<sub>revoot/");
    output.push_str(env!("CARGO_PKG_VERSION"));
    output.push(' ');
    if let Some(job_url) = &metadata.job_url {
        output.push_str("<a href=\"");
        output.push_str(&escape_attribute(job_url));
        output.push_str("\">reviewed</a>");
    } else {
        output.push_str("reviewed");
    }
    output.push_str(" via <code>");
    output.push_str(&escape_text(&metadata.provider_model));
    output.push_str("</code> at <code>");
    output.push_str(&metadata.commit.as_str()[..12]);
    output.push_str("</code></sub>\n\n</details>\n");
    if let Some(checkpoint) = &metadata.checkpoint {
        output.push_str(&checkpoint.render());
        output.push('\n');
    }
    output.push_str(OVERVIEW_END);
    if output.len() > MAX_OVERVIEW_BYTES {
        return Err(ReviewOverviewError::InvalidOverview);
    }
    Ok(output)
}

/// Replace exactly one owned block or append one without changing surrounding bytes.
///
/// # Errors
///
/// Rejects oversized descriptions, invalid replacement blocks, or ambiguous
/// ownership markers.
pub fn update_description(
    description: &str,
    overview_block: &str,
) -> Result<String, ReviewOverviewError> {
    if description.len() > MAX_DESCRIPTION_BYTES
        || overview_block.len() > MAX_OVERVIEW_BYTES
        || !overview_block.starts_with(OVERVIEW_START)
        || !overview_block.ends_with(OVERVIEW_END)
    {
        return Err(ReviewOverviewError::InvalidDescription);
    }
    let starts = description
        .match_indices(OVERVIEW_START)
        .collect::<Vec<_>>();
    let ends = description.match_indices(OVERVIEW_END).collect::<Vec<_>>();
    let updated = match (starts.as_slice(), ends.as_slice()) {
        ([], []) if description.is_empty() => overview_block.to_owned(),
        ([], []) => format!("{description}\n\n{overview_block}"),
        ([(start, _)], [(end, _)]) if start < end => {
            let end = end
                .checked_add(OVERVIEW_END.len())
                .ok_or(ReviewOverviewError::DescriptionTooLarge)?;
            format!(
                "{}{}{}",
                &description[..*start],
                overview_block,
                &description[end..]
            )
        }
        _ => return Err(ReviewOverviewError::AmbiguousMarkers),
    };
    if updated.len() > MAX_DESCRIPTION_BYTES {
        return Err(ReviewOverviewError::DescriptionTooLarge);
    }
    Ok(updated)
}

fn render_list(output: &mut String, heading: &str, items: &[String]) {
    if items.is_empty() {
        return;
    }
    output.push_str("\n<h3>");
    output.push_str(heading);
    output.push_str("</h3>\n\n");
    for item in items {
        output.push_str("- ");
        output.push_str(&escape_text(item));
        output.push('\n');
    }
}

fn valid_line(value: &str, maximum: usize) -> bool {
    !value.trim().is_empty()
        && value.len() <= maximum
        && value == value.trim()
        && !value.chars().any(char::is_control)
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/')
        })
}

fn validate_job_url(value: &str) -> Result<String, ReviewOverviewError> {
    if value.len() > MAX_JOB_URL_BYTES {
        return Err(ReviewOverviewError::InvalidMetadata);
    }
    let url = Url::parse(value).map_err(|_| ReviewOverviewError::InvalidMetadata)?;
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.host_str().is_none()
        || url.fragment().is_some()
    {
        return Err(ReviewOverviewError::InvalidMetadata);
    }
    Ok(url.to_string())
}

fn escape_text(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '&' => output.push_str("&amp;"),
            '<' => output.push_str("&lt;"),
            '>' => output.push_str("&gt;"),
            '`' => output.push_str("&#96;"),
            '*' => output.push_str("&#42;"),
            '_' => output.push_str("&#95;"),
            '[' => output.push_str("&#91;"),
            ']' => output.push_str("&#93;"),
            '\\' => output.push_str("&#92;"),
            _ => output.push(character),
        }
    }
    output
}

fn escape_table_text(value: &str) -> String {
    escape_text(value).replace('|', "&#124;")
}

fn escape_attribute(value: &str) -> String {
    escape_text(value)
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn overview() -> ReviewOverview {
        ReviewOverview {
            summary: "Changes authentication persistence and deployment ordering.".to_owned(),
            overall_risk: RiskLevel::High,
            overall_basis: "Authentication and data migration change together.".to_owned(),
            risks: vec![ReviewRisk {
                area: "Data migration".to_owned(),
                risk: RiskLevel::High,
                basis: "No rollback path was observed.".to_owned(),
            }],
            assumptions_and_gaps: vec!["Assumes migration completes before deployment.".to_owned()],
            manual_validations: vec!["Exercise rollback using production-shaped data.".to_owned()],
        }
    }

    fn metadata() -> ReviewRunMetadata {
        ReviewRunMetadata::try_new(
            "anthropic",
            "claude-opus-5",
            GitSha::try_from("a".repeat(40)).unwrap(),
            Some("https://github.com/acme/repo/actions/runs/42"),
        )
        .unwrap()
    }

    #[test]
    fn renders_shared_details_block_and_versioned_linked_footer() {
        let checkpoint = ReviewCheckpoint::current(
            GitSha::try_from("b".repeat(40)).unwrap(),
            GitSha::try_from("a".repeat(40)).unwrap(),
            revoot_core::Sha256Digest::of_bytes(b"manifest"),
            true,
            0,
        );
        let rendered =
            render_review_overview(&overview(), &metadata().with_checkpoint(checkpoint.clone()))
                .unwrap();
        assert!(rendered.starts_with(OVERVIEW_START));
        assert!(rendered.contains("<details>"));
        assert!(rendered.contains("Revoot overview · High risk"));
        assert!(
            rendered
                .contains("<a href=\"https://github.com/acme/repo/actions/runs/42\">reviewed</a>")
        );
        assert!(rendered.contains(concat!("revoot/", env!("CARGO_PKG_VERSION"))));
        assert!(rendered.contains("<code>anthropic/claude-opus-5</code>"));
        assert!(rendered.contains("<code>aaaaaaaaaaaa</code>"));
        assert_eq!(
            crate::review_checkpoint::extract_checkpoint(&rendered),
            Some(checkpoint)
        );
        assert!(rendered.ends_with(OVERVIEW_END));
    }

    #[test]
    fn replacement_preserves_every_byte_outside_the_owned_block() {
        let first = render_review_overview(&overview(), &metadata()).unwrap();
        let description = format!("author prefix\n\n{first}\n\nauthor suffix");
        let mut changed = overview();
        changed.overall_risk = RiskLevel::Moderate;
        changed.risks[0].risk = RiskLevel::Moderate;
        let second = render_review_overview(&changed, &metadata()).unwrap();
        let updated = update_description(&description, &second).unwrap();
        assert_eq!(
            updated,
            format!("author prefix\n\n{second}\n\nauthor suffix")
        );
        assert_eq!(update_description(&updated, &second).unwrap(), updated);
    }

    #[test]
    fn malformed_duplicate_or_injected_markers_fail_closed() {
        let block = render_review_overview(&overview(), &metadata()).unwrap();
        assert_eq!(
            update_description(&format!("{OVERVIEW_START}\nmissing end"), &block),
            Err(ReviewOverviewError::AmbiguousMarkers)
        );
        assert_eq!(
            update_description(&format!("{block}\n{block}"), &block),
            Err(ReviewOverviewError::AmbiguousMarkers)
        );
        let mut injected = overview();
        injected.summary = "<!-- revoot:overview:v1:end -->".to_owned();
        let escaped = render_review_overview(&injected, &metadata()).unwrap();
        assert_eq!(escaped.matches(OVERVIEW_END).count(), 1);
    }

    #[test]
    fn bounds_and_metadata_are_closed() {
        let mut invalid = overview();
        invalid.risks.resize(5, invalid.risks[0].clone());
        assert_eq!(
            render_review_overview(&invalid, &metadata()),
            Err(ReviewOverviewError::InvalidOverview)
        );
        assert!(
            ReviewRunMetadata::try_new(
                "anthropic",
                "model",
                GitSha::try_from("b".repeat(40)).unwrap(),
                Some("javascript:alert(1)"),
            )
            .is_err()
        );

        let mut low_row = overview();
        low_row.risks[0].risk = RiskLevel::Low;
        assert_eq!(
            low_row.validate(),
            Err(ReviewOverviewError::InvalidOverview)
        );

        let mut understated = overview();
        understated.overall_risk = RiskLevel::Moderate;
        assert_eq!(
            understated.validate(),
            Err(ReviewOverviewError::InvalidOverview)
        );
    }
}
