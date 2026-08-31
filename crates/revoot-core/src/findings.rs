//! Strict model-output validation, deterministic ranking, and safe rendering.
//!
//! Model output remains untrusted after JSON-schema validation. This module
//! binds every finding to an issued work-unit anchor, rejects unsafe Markdown,
//! deduplicates by a stable logical finding key, and renders bounded GitLab
//! comment bodies without performing any network or publication operation.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    AnchorId, AnchorPosition, AnchorTable, ReviewSnapshotIdentity, Sha256Digest, TrustedAnchor,
};

const MAX_WORK_UNIT_ID_BYTES: usize = 128;
const MAX_ANCHOR_ID_BYTES: usize = 128;
const MAX_TITLE_BYTES: usize = 160;
const MAX_EXPLANATION_BYTES: usize = 4_000;
const MAX_EVIDENCE_BYTES: usize = 2_000;
const MAX_REPLACEMENT_BYTES: usize = 8_000;
const MAX_SUMMARY_BYTES: usize = 4_000;
const MAX_REVIEW_FINDINGS: usize = 250;
const REVOOT_MARKER_PREFIX: &str = "<!-- revoot:";

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl Severity {
    const fn priority(self) -> u8 {
        match self {
            Self::Critical => 5,
            Self::High => 4,
            Self::Medium => 3,
            Self::Low => 2,
            Self::Info => 1,
        }
    }

    const fn presentation(self) -> (&'static str, &'static str, &'static str) {
        match self {
            Self::Critical => ("🔴", "P1", "Critical"),
            Self::High => ("🟠", "P2", "High"),
            Self::Medium => ("🟡", "P3", "Medium"),
            Self::Low => ("🟢", "P4", "Low"),
            Self::Info => ("🔵", "P5", "Info"),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingCategory {
    Correctness,
    Security,
    Reliability,
    Performance,
    Maintainability,
}

impl FindingCategory {
    const fn label(self) -> &'static str {
        match self {
            Self::Correctness => "correctness",
            Self::Security => "security",
            Self::Reliability => "reliability",
            Self::Performance => "performance",
            Self::Maintainability => "maintainability",
        }
    }

    const fn presentation(self) -> &'static str {
        match self {
            Self::Correctness => "Correctness",
            Self::Security => "Security",
            Self::Reliability => "Reliability",
            Self::Performance => "Performance",
            Self::Maintainability => "Maintainability",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Finding {
    pub anchor_id: String,
    pub severity: Severity,
    pub confidence_percent: u8,
    pub category: FindingCategory,
    pub title: String,
    pub explanation: String,
    pub evidence: String,
    /// Existing host-backed lineage selected after semantic comparison with
    /// prior review discussions. Omitted for a genuinely new issue.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lineage_id: Option<Sha256Digest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub suggested_replacement: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FindingsEnvelope {
    pub schema_version: String,
    pub work_unit_id: String,
    pub findings: Vec<Finding>,
    pub summary: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FindingsValidationError {
    SchemaVersion,
    WorkUnitId,
    TooManyFindings,
    AnchorId,
    Confidence,
    Category,
    Title,
    Explanation,
    Evidence,
    SuggestedReplacement,
    Summary,
    ControlCharacter,
    MarkerInjection,
    QuickAction,
    UnsafeUrlScheme,
    ExternalLink,
}

impl FindingsEnvelope {
    pub const MAX_FINDINGS: usize = 25;
    pub const SCHEMA_VERSION: &'static str = "revoot.findings/v1";

    /// Validate the narrow, bounded semantic contract.
    ///
    /// # Errors
    ///
    /// Returns the first violated schema, size, or content invariant.
    pub fn validate(&self) -> Result<(), FindingsValidationError> {
        if self.schema_version != Self::SCHEMA_VERSION {
            return Err(FindingsValidationError::SchemaVersion);
        }
        if !valid_label(&self.work_unit_id, MAX_WORK_UNIT_ID_BYTES) {
            return Err(FindingsValidationError::WorkUnitId);
        }
        if self.findings.len() > Self::MAX_FINDINGS {
            return Err(FindingsValidationError::TooManyFindings);
        }
        validate_markdown(&self.summary, MAX_SUMMARY_BYTES)
            .map_err(|error| map_content_error(error, FindingsValidationError::Summary))?;
        for finding in &self.findings {
            if !valid_label(&finding.anchor_id, MAX_ANCHOR_ID_BYTES) {
                return Err(FindingsValidationError::AnchorId);
            }
            if finding.confidence_percent > 100 {
                return Err(FindingsValidationError::Confidence);
            }
            if finding.title.is_empty()
                || finding.title.len() > MAX_TITLE_BYTES
                || finding.title.trim() != finding.title
                || finding.title.contains(['\n', '\r'])
            {
                return Err(FindingsValidationError::Title);
            }
            validate_plain_text(&finding.title)
                .map_err(|error| map_content_error(error, FindingsValidationError::Title))?;
            validate_markdown(&finding.explanation, MAX_EXPLANATION_BYTES)
                .map_err(|error| map_content_error(error, FindingsValidationError::Explanation))?;
            validate_markdown(&finding.evidence, MAX_EVIDENCE_BYTES)
                .map_err(|error| map_content_error(error, FindingsValidationError::Evidence))?;
            if let Some(replacement) = &finding.suggested_replacement {
                validate_replacement(replacement).map_err(|error| {
                    map_content_error(error, FindingsValidationError::SuggestedReplacement)
                })?;
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ContentError {
    Field,
    ControlCharacter,
    MarkerInjection,
    QuickAction,
    UnsafeUrlScheme,
    ExternalLink,
}

const fn map_content_error(
    error: ContentError,
    field: FindingsValidationError,
) -> FindingsValidationError {
    match error {
        ContentError::Field => field,
        ContentError::ControlCharacter => FindingsValidationError::ControlCharacter,
        ContentError::MarkerInjection => FindingsValidationError::MarkerInjection,
        ContentError::QuickAction => FindingsValidationError::QuickAction,
        ContentError::UnsafeUrlScheme => FindingsValidationError::UnsafeUrlScheme,
        ContentError::ExternalLink => FindingsValidationError::ExternalLink,
    }
}

fn valid_label(value: &str, max_bytes: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_bytes
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/')
        })
}

fn validate_plain_text(value: &str) -> Result<(), ContentError> {
    if value
        .chars()
        .any(|character| character.is_control() && character != '\t')
    {
        return Err(ContentError::ControlCharacter);
    }
    let lowercase = value.to_ascii_lowercase();
    if lowercase.contains(REVOOT_MARKER_PREFIX) {
        return Err(ContentError::MarkerInjection);
    }
    if contains_link_or_image(value, &lowercase) {
        return Err(ContentError::ExternalLink);
    }
    Ok(())
}

fn validate_markdown(value: &str, max_bytes: usize) -> Result<(), ContentError> {
    if value.trim().is_empty() || value.len() > max_bytes {
        return Err(ContentError::Field);
    }
    if value
        .chars()
        .any(|character| character.is_control() && !matches!(character, '\n' | '\t'))
    {
        return Err(ContentError::ControlCharacter);
    }
    let lowercase = value.to_ascii_lowercase();
    if lowercase.contains(REVOOT_MARKER_PREFIX) {
        return Err(ContentError::MarkerInjection);
    }
    if contains_unsafe_url(&lowercase) {
        return Err(ContentError::UnsafeUrlScheme);
    }
    if contains_link_or_image(value, &lowercase) {
        return Err(ContentError::ExternalLink);
    }
    if value
        .lines()
        .any(|line| line.trim_start().starts_with('/') && !line.trim_start().starts_with("//"))
    {
        return Err(ContentError::QuickAction);
    }
    Ok(())
}

fn contains_link_or_image(value: &str, lowercase: &str) -> bool {
    value.contains("](")
        || value.contains("![")
        || ["http://", "https://", "mailto:"]
            .into_iter()
            .any(|scheme| lowercase.contains(scheme))
}

fn contains_unsafe_url(lowercase: &str) -> bool {
    ["javascript:", "vbscript:", "data:", "file:"]
        .into_iter()
        .any(|scheme| {
            lowercase.match_indices(scheme).any(|(index, _)| {
                let prefix = lowercase[..index].trim_end();
                prefix.ends_with('(') || prefix.ends_with('<')
            })
        })
}

fn validate_replacement(value: &str) -> Result<(), ContentError> {
    if value.is_empty() || value.len() > MAX_REPLACEMENT_BYTES {
        return Err(ContentError::Field);
    }
    if value
        .chars()
        .any(|character| character.is_control() && !matches!(character, '\n' | '\t'))
    {
        return Err(ContentError::ControlCharacter);
    }
    if value.to_ascii_lowercase().contains(REVOOT_MARKER_PREFIX) {
        return Err(ContentError::MarkerInjection);
    }
    Ok(())
}

/// Exact allowlist of opaque anchors issued to each work unit.
pub type IssuedWorkUnitAnchors = BTreeMap<String, BTreeSet<AnchorId>>;

/// One trusted, ranked finding ready for deterministic publication planning.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RankedFinding {
    pub work_unit_id: String,
    pub anchor_id: AnchorId,
    pub severity: Severity,
    pub confidence_percent: u8,
    pub category: FindingCategory,
    pub finding_key: Sha256Digest,
    pub content_digest: Sha256Digest,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lineage_id: Option<Sha256Digest>,
    pub rendered_body: String,
}

/// Validated aggregate output. Duplicate findings are explicitly counted.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RankedFindings {
    pub findings: Vec<RankedFinding>,
    pub unit_summaries: BTreeMap<String, String>,
    pub duplicates_omitted: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FindingsPipelineError {
    Envelope(FindingsValidationError),
    DuplicateWorkUnit,
    UnknownWorkUnit,
    InvalidAnchorShape,
    AnchorNotIssued,
    AnchorNotTrusted,
    ReviewFindingLimit,
    DuplicateOverflow,
}

/// Validate, bind, safely render, deduplicate, and rank model findings.
///
/// # Errors
///
/// Fails the entire aggregate if any envelope, work-unit ID, anchor, content,
/// or review-wide bound is invalid. No fragments are salvaged.
pub fn validate_rank_and_render(
    envelopes: impl IntoIterator<Item = FindingsEnvelope>,
    issued: &IssuedWorkUnitAnchors,
    anchors: &AnchorTable,
    max_review_findings: usize,
) -> Result<RankedFindings, FindingsPipelineError> {
    if max_review_findings == 0 || max_review_findings > MAX_REVIEW_FINDINGS {
        return Err(FindingsPipelineError::ReviewFindingLimit);
    }
    let mut seen_units = BTreeSet::new();
    let mut summaries = BTreeMap::new();
    let mut by_key: BTreeMap<Sha256Digest, RankedFinding> = BTreeMap::new();
    let mut duplicates = 0_u32;
    let mut input_findings = 0_usize;

    for envelope in envelopes {
        envelope
            .validate()
            .map_err(FindingsPipelineError::Envelope)?;
        if !seen_units.insert(envelope.work_unit_id.clone()) {
            return Err(FindingsPipelineError::DuplicateWorkUnit);
        }
        let allowed = issued
            .get(&envelope.work_unit_id)
            .ok_or(FindingsPipelineError::UnknownWorkUnit)?;
        summaries.insert(
            envelope.work_unit_id.clone(),
            render_safe_markdown(&envelope.summary),
        );
        for finding in envelope.findings {
            input_findings = input_findings
                .checked_add(1)
                .ok_or(FindingsPipelineError::ReviewFindingLimit)?;
            if input_findings > max_review_findings {
                return Err(FindingsPipelineError::ReviewFindingLimit);
            }
            let anchor_id = AnchorId::try_from(finding.anchor_id.clone())
                .map_err(|_| FindingsPipelineError::InvalidAnchorShape)?;
            if !allowed.contains(&anchor_id) {
                return Err(FindingsPipelineError::AnchorNotIssued);
            }
            let anchor = anchors
                .resolve(anchor_id.as_str())
                .ok_or(FindingsPipelineError::AnchorNotTrusted)?;
            let ranked = rankable_finding(
                &envelope.work_unit_id,
                anchor_id,
                anchor,
                anchors.identity(),
                &finding,
            );
            match by_key.entry(ranked.finding_key.clone()) {
                std::collections::btree_map::Entry::Vacant(entry) => {
                    entry.insert(ranked);
                }
                std::collections::btree_map::Entry::Occupied(mut entry) => {
                    duplicates = duplicates
                        .checked_add(1)
                        .ok_or(FindingsPipelineError::DuplicateOverflow)?;
                    if ranked_preference(&ranked, entry.get()) == Ordering::Less {
                        entry.insert(ranked);
                    }
                }
            }
        }
    }

    if by_key.len() > max_review_findings {
        return Err(FindingsPipelineError::ReviewFindingLimit);
    }
    let mut findings: Vec<_> = by_key.into_values().collect();
    findings.sort_by(ranked_preference);
    Ok(RankedFindings {
        findings,
        unit_summaries: summaries,
        duplicates_omitted: duplicates,
    })
}

fn rankable_finding(
    work_unit_id: &str,
    anchor_id: AnchorId,
    anchor: &TrustedAnchor,
    snapshot: &ReviewSnapshotIdentity,
    finding: &Finding,
) -> RankedFinding {
    let finding_key = finding_key(snapshot, anchor, finding.category, &finding.title);
    let rendered_body = render_finding(finding);
    let content_digest = Sha256Digest::of_bytes(rendered_body.as_bytes());
    RankedFinding {
        work_unit_id: work_unit_id.to_owned(),
        anchor_id,
        severity: finding.severity,
        confidence_percent: finding.confidence_percent,
        category: finding.category,
        finding_key,
        content_digest,
        lineage_id: finding.lineage_id.clone(),
        rendered_body,
    }
}

fn finding_key(
    snapshot: &ReviewSnapshotIdentity,
    anchor: &TrustedAnchor,
    category: FindingCategory,
    title: &str,
) -> Sha256Digest {
    let logical_path = match anchor.position {
        AnchorPosition::Deletion { .. } => anchor.path.old_path.as_str(),
        AnchorPosition::Addition { .. } | AnchorPosition::Context { .. } => {
            anchor.path.new_path.as_str()
        }
    };
    let side = match anchor.position {
        AnchorPosition::Deletion { .. } => "old",
        AnchorPosition::Addition { .. } | AnchorPosition::Context { .. } => "new",
    };
    let normalized_title = title
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase();
    let mut hasher = Sha256::new();
    let mut identity_fields = Vec::new();
    match snapshot {
        ReviewSnapshotIdentity::GitLab(identity) => {
            identity_fields.push(b"revoot-finding-key-v1".as_slice());
            identity_fields.push(
                identity
                    .version
                    .scope
                    .instance_origin_digest
                    .as_str()
                    .as_bytes(),
            );
            let project_id = identity.version.scope.project_id.get().to_be_bytes();
            identity_fields.push(&project_id);
            for field in identity_fields {
                hasher.update(u64::try_from(field.len()).unwrap_or(u64::MAX).to_be_bytes());
                hasher.update(field);
            }
        }
        ReviewSnapshotIdentity::GitHub(identity) => {
            for field in [
                b"revoot-github-finding-key-v1".as_slice(),
                identity.api_origin_digest.as_str().as_bytes(),
                &identity.repository_id.get().to_be_bytes(),
            ] {
                hasher.update(u64::try_from(field.len()).unwrap_or(u64::MAX).to_be_bytes());
                hasher.update(field);
            }
        }
        ReviewSnapshotIdentity::Local(identity) => {
            for field in [
                b"revoot-local-finding-key-v1".as_slice(),
                identity.repository_identity_sha256.as_str().as_bytes(),
            ] {
                hasher.update(u64::try_from(field.len()).unwrap_or(u64::MAX).to_be_bytes());
                hasher.update(field);
            }
        }
    }
    for field in [
        logical_path.as_bytes(),
        side.as_bytes(),
        anchor.context_digest.as_str().as_bytes(),
        category.label().as_bytes(),
        normalized_title.as_bytes(),
    ] {
        hasher.update(u64::try_from(field.len()).unwrap_or(u64::MAX).to_be_bytes());
        hasher.update(field);
    }
    Sha256Digest::try_from(format!("{:x}", hasher.finalize())).expect("SHA-256 formatting is valid")
}

fn ranked_preference(left: &RankedFinding, right: &RankedFinding) -> Ordering {
    right
        .severity
        .priority()
        .cmp(&left.severity.priority())
        .then_with(|| right.confidence_percent.cmp(&left.confidence_percent))
        .then_with(|| left.finding_key.cmp(&right.finding_key))
        .then_with(|| left.content_digest.cmp(&right.content_digest))
        .then_with(|| left.anchor_id.cmp(&right.anchor_id))
}

fn render_finding(finding: &Finding) -> String {
    let title = render_safe_markdown(&finding.title);
    let explanation = render_safe_markdown(&finding.explanation);
    let evidence = render_safe_markdown(&finding.evidence);
    let (severity_icon, priority, severity_label) = finding.severity.presentation();
    let mut body = format!(
        "**[Revoot](https://github.com/getrevoot/revoot)**\n\n\
         | Severity | Category | Confidence |\n\
         | --- | --- | --- |\n\
         | {severity_icon} **{priority} ({severity_label})** | {} | {} |\n\n\
         ### {title}\n\n{}\n\n{}",
        finding.category.presentation(),
        confidence_label(finding.confidence_percent),
        explanation,
        evidence
    );
    if let Some(replacement) = &finding.suggested_replacement {
        let fence = code_fence(replacement);
        body.push_str("\n\n#### Suggested fix\n\n");
        body.push_str(&fence);
        body.push('\n');
        body.push_str(replacement);
        if !replacement.ends_with('\n') {
            body.push('\n');
        }
        body.push_str(&fence);
    }
    body
}

const fn confidence_label(confidence_percent: u8) -> &'static str {
    match confidence_percent {
        0 => "N/A",
        1..=69 => "Low",
        70..=89 => "Medium",
        90..=u8::MAX => "High",
    }
}

fn render_safe_markdown(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn code_fence(value: &str) -> String {
    let longest = value
        .split(|character| character != '`')
        .map(str::len)
        .max()
        .unwrap_or(0);
    "`".repeat(longest.saturating_add(1).max(3))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AnchorPosition, ChangedPath, CommentableLine, DiffRefs, DiffVersionId, DiffVersionRecord,
        FileChangeKind, GitLabDiffVersionIdentity, MergeRequestIid, ProjectId, RepositoryPath,
        SnapshotScope,
    };

    fn digest(marker: char) -> Sha256Digest {
        Sha256Digest::try_from(marker.to_string().repeat(64)).unwrap()
    }

    fn anchor_table() -> AnchorTable {
        let identity = GitLabDiffVersionIdentity {
            scope: SnapshotScope {
                instance_origin_digest: digest('a'),
                project_id: ProjectId::try_from(1).unwrap(),
                merge_request_iid: MergeRequestIid::try_from(2).unwrap(),
            },
            diff_version: DiffVersionRecord {
                id: DiffVersionId::try_from(3).unwrap(),
                refs: DiffRefs {
                    base_sha: "b".repeat(40).try_into().unwrap(),
                    start_sha: "c".repeat(40).try_into().unwrap(),
                    head_sha: "d".repeat(40).try_into().unwrap(),
                },
            },
        }
        .freeze(digest('e'));
        AnchorTable::build(
            identity,
            [CommentableLine {
                path: ChangedPath {
                    old_path: RepositoryPath::try_from("src/lib.rs".to_owned()).unwrap(),
                    new_path: RepositoryPath::try_from("src/lib.rs".to_owned()).unwrap(),
                    kind: FileChangeKind::Modified,
                },
                position: AnchorPosition::addition(10).unwrap(),
                exact_line_digest: digest('1'),
                context_digest: digest('2'),
            }],
        )
        .unwrap()
    }

    fn finding(anchor_id: &str, severity: Severity, confidence: u8) -> Finding {
        Finding {
            anchor_id: anchor_id.to_owned(),
            severity,
            confidence_percent: confidence,
            category: FindingCategory::Correctness,
            title: "Unchecked state transition".to_owned(),
            explanation: "The state changes before validation.".to_owned(),
            evidence: "The mutation is visible on this line.".to_owned(),
            lineage_id: None,
            suggested_replacement: None,
        }
    }

    #[test]
    fn finding_comment_uses_branded_metadata_and_one_body() {
        let mut value = finding("anchor-1", Severity::Medium, 85);
        value.title = "Avoid the fallback path".to_owned();
        value.explanation = "The fallback changes successful requests.".to_owned();
        value.evidence = "The caller reaches this branch for every retry.".to_owned();
        value.suggested_replacement = Some("return primary;".to_owned());

        let rendered = render_finding(&value);

        assert!(rendered.starts_with(
            "**[Revoot](https://github.com/getrevoot/revoot)**\n\n\
             | Severity | Category | Confidence |\n\
             | --- | --- | --- |\n\
             | 🟡 **P3 (Medium)** | Correctness | Medium |"
        ));
        assert!(rendered.contains("### Avoid the fallback path"));
        assert!(rendered.contains(
            "The fallback changes successful requests.\n\n\
             The caller reaches this branch for every retry."
        ));
        assert!(rendered.contains("#### Suggested fix\n\n```\nreturn primary;\n```"));
        assert!(!rendered.contains("**Evidence**"));
        assert!(!rendered.contains("Suggested replacement"));
    }

    #[test]
    fn severity_and_confidence_presentations_cover_the_public_taxonomy() {
        assert_eq!(Severity::Critical.presentation(), ("🔴", "P1", "Critical"));
        assert_eq!(Severity::High.presentation(), ("🟠", "P2", "High"));
        assert_eq!(Severity::Medium.presentation(), ("🟡", "P3", "Medium"));
        assert_eq!(Severity::Low.presentation(), ("🟢", "P4", "Low"));
        assert_eq!(Severity::Info.presentation(), ("🔵", "P5", "Info"));

        assert_eq!(confidence_label(95), "High");
        assert_eq!(confidence_label(85), "Medium");
        assert_eq!(confidence_label(60), "Low");
        assert_eq!(confidence_label(0), "N/A");
    }

    fn envelope(anchor_id: &str, finding: Finding) -> FindingsEnvelope {
        FindingsEnvelope {
            schema_version: FindingsEnvelope::SCHEMA_VERSION.to_owned(),
            work_unit_id: "wu-1".to_owned(),
            findings: vec![finding],
            summary: format!("Reviewed anchor `{anchor_id}`."),
        }
    }

    #[test]
    fn golden_findings_vector_parses_and_validates() {
        let envelope: FindingsEnvelope = serde_json::from_str(include_str!(
            "../../../contracts/golden/findings-v1.valid.json"
        ))
        .unwrap();
        assert_eq!(envelope.validate(), Ok(()));
    }

    #[test]
    fn rejects_duplicate_json_fields_and_unsafe_markdown() {
        let duplicate = br#"{"schema_version":"revoot.findings/v1","schema_version":"revoot.findings/v1","work_unit_id":"wu-1","findings":[],"summary":"ok"}"#;
        assert!(serde_json::from_slice::<FindingsEnvelope>(duplicate).is_err());

        let table = anchor_table();
        let anchor_id = table.iter().next().unwrap().id.as_str();
        let mut unsafe_envelope = envelope(anchor_id, finding(anchor_id, Severity::High, 90));
        unsafe_envelope.findings[0].explanation = "/approve".to_owned();
        assert_eq!(
            unsafe_envelope.validate(),
            Err(FindingsValidationError::QuickAction)
        );
        unsafe_envelope.findings[0].explanation = "[click](javascript:alert(1))".to_owned();
        assert_eq!(
            unsafe_envelope.validate(),
            Err(FindingsValidationError::UnsafeUrlScheme)
        );
        unsafe_envelope.findings[0].explanation =
            "The parsed data: value is ordinary prose.".to_owned();
        assert_eq!(unsafe_envelope.validate(), Ok(()));

        unsafe_envelope.findings[0].explanation =
            "Inspect [this report](https://attacker.invalid/collect).".to_owned();
        assert_eq!(
            unsafe_envelope.validate(),
            Err(FindingsValidationError::ExternalLink)
        );
        unsafe_envelope.findings[0].explanation =
            "![tracking pixel](relative-image.png)".to_owned();
        assert_eq!(
            unsafe_envelope.validate(),
            Err(FindingsValidationError::ExternalLink)
        );
        unsafe_envelope.findings[0].explanation = "Safe explanation.".to_owned();
        unsafe_envelope.findings[0].title = "See https://attacker.invalid".to_owned();
        assert_eq!(
            unsafe_envelope.validate(),
            Err(FindingsValidationError::ExternalLink)
        );
    }

    #[test]
    fn exact_issued_anchor_is_required_and_html_is_escaped() {
        let table = anchor_table();
        let anchor_id = table.iter().next().unwrap().id.clone();
        let mut value = finding(anchor_id.as_str(), Severity::High, 90);
        value.evidence = "`value` <script>".to_owned();
        let issued = BTreeMap::from([("wu-1".to_owned(), BTreeSet::from([anchor_id.clone()]))]);
        let ranked =
            validate_rank_and_render([envelope(anchor_id.as_str(), value)], &issued, &table, 10)
                .unwrap();
        assert_eq!(ranked.findings.len(), 1);
        assert!(ranked.findings[0].rendered_body.contains("&lt;script&gt;"));

        let empty = BTreeMap::from([("wu-1".to_owned(), BTreeSet::new())]);
        assert_eq!(
            validate_rank_and_render(
                [envelope(
                    anchor_id.as_str(),
                    finding(anchor_id.as_str(), Severity::High, 90)
                )],
                &empty,
                &table,
                10,
            ),
            Err(FindingsPipelineError::AnchorNotIssued)
        );
    }

    #[test]
    fn duplicate_key_keeps_deterministically_higher_ranked_finding() {
        let table = anchor_table();
        let anchor_id = table.iter().next().unwrap().id.clone();
        let issued = BTreeMap::from([
            ("wu-1".to_owned(), BTreeSet::from([anchor_id.clone()])),
            ("wu-2".to_owned(), BTreeSet::from([anchor_id.clone()])),
        ]);
        let low = envelope(
            anchor_id.as_str(),
            finding(anchor_id.as_str(), Severity::Low, 60),
        );
        let mut high = envelope(
            anchor_id.as_str(),
            finding(anchor_id.as_str(), Severity::High, 95),
        );
        high.work_unit_id = "wu-2".to_owned();
        let first =
            validate_rank_and_render([low.clone(), high.clone()], &issued, &table, 10).unwrap();
        let second = validate_rank_and_render([high, low], &issued, &table, 10).unwrap();
        assert_eq!(first, second);
        assert_eq!(first.duplicates_omitted, 1);
        assert_eq!(first.findings[0].severity, Severity::High);
    }

    #[test]
    fn rejects_wrong_schema_version() {
        let envelope = FindingsEnvelope {
            schema_version: "revoot.findings/v2".to_owned(),
            work_unit_id: "wu-1".to_owned(),
            findings: Vec::new(),
            summary: "No findings.".to_owned(),
        };
        assert_eq!(
            envelope.validate(),
            Err(FindingsValidationError::SchemaVersion)
        );
    }
}
