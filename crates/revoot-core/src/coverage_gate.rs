//! Coverage-delivery ledger and telemetry for risk-adaptive group review.
//!
//! The gate records only trusted delivery events. Completion is the caller's
//! (the model's) voluntary signal - unmet ledger requirements are recorded as
//! telemetry, never a rejection - but a local budget or tool failure still
//! makes an otherwise policy-complete group `Partial` instead of `Complete`.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::{
    CoverageError, FileCoverageLedger, GroupCoverageLedger, RepositoryPath, UnreadHunkDisposition,
    UnreadHunkDispositionKind,
};

const MAX_DISPOSITION_NOTE_BYTES: usize = 512;

/// A deterministic cause that prevents a successful group from being full.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GroupPartialCause {
    BudgetExhausted,
    ToolError,
}

/// Successful terminal state returned only after all coverage requirements.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum GroupCompletion {
    Complete {
        policy_version: String,
        low_risk_deferrals: u32,
    },
    Partial {
        policy_version: String,
        causes: BTreeSet<GroupPartialCause>,
        low_risk_deferrals: u32,
    },
}

/// Stable, payload-free construction failure for an invalid ledger.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoverageGateError {
    PolicyVersion,
    FileBinding,
    InvalidHunk,
    DuplicateHunk,
    InvalidDisposition,
    InvalidMetadataOnlyRename,
    MetadataRenameNotFound,
    PageAlreadyDelivered,
    Ledger(CoverageError),
}

/// Mutable trusted delivery ledger and one-way terminal completion gate.
pub struct CoverageCompletionGate {
    ledger: GroupCoverageLedger,
    partial_causes: BTreeSet<GroupPartialCause>,
}

impl CoverageCompletionGate {
    /// Validate a coverage ledger and trusted metadata-only rename allowlist.
    ///
    /// # Errors
    ///
    /// Rejects forged policy versions, map/file mismatches, malformed or
    /// duplicate hunks, invalid dispositions, and metadata-only files not
    /// independently established as renames.
    pub fn new(
        ledger: GroupCoverageLedger,
        metadata_only_renames: &BTreeSet<RepositoryPath>,
    ) -> Result<Self, CoverageGateError> {
        validate_ledger(&ledger, metadata_only_renames)?;
        let partial_causes = disposition_partial_causes(&ledger);
        Ok(Self {
            ledger,
            partial_causes,
        })
    }

    /// Return current trusted coverage state.
    #[must_use]
    pub const fn ledger(&self) -> &GroupCoverageLedger {
        &self.ledger
    }

    /// Record actual delivery of one file manifest.
    ///
    /// # Errors
    ///
    /// Returns a payload-free ledger error for an unknown file.
    pub fn mark_manifested(&mut self, path: &RepositoryPath) -> Result<(), CoverageGateError> {
        self.ledger
            .mark_manifested(path)
            .map_err(CoverageGateError::Ledger)
    }

    /// Record actual delivery of one exact hunk page.
    ///
    /// # Errors
    ///
    /// Returns a payload-free ledger error for unknown or invalid targets.
    pub fn record_hunk_page(
        &mut self,
        path: &RepositoryPath,
        hunk_id: &str,
        page: u32,
    ) -> Result<(), CoverageGateError> {
        validate_undelivered_hunk_page(&self.ledger, path, hunk_id, page)?;
        self.ledger
            .record_hunk_page(path, hunk_id, page)
            .map_err(CoverageGateError::Ledger)
    }

    /// Atomically record a batch of successfully delivered hunk pages.
    ///
    /// # Errors
    ///
    /// Returns a payload-free ledger error without changing coverage when any
    /// page in the batch has an unknown or invalid target.
    pub fn record_hunk_pages(
        &mut self,
        pages: &[(RepositoryPath, String, u32)],
    ) -> Result<(), CoverageGateError> {
        let mut unique = BTreeSet::new();
        for (path, hunk_id, page) in pages {
            if !unique.insert((path, hunk_id, page)) {
                return Err(CoverageGateError::PageAlreadyDelivered);
            }
            validate_undelivered_hunk_page(&self.ledger, path, hunk_id, *page)?;
        }
        for (path, hunk_id, page) in pages {
            self.ledger
                .record_hunk_page(path, hunk_id, *page)
                .map_err(CoverageGateError::Ledger)?;
        }
        Ok(())
    }

    /// Record one explicit unread disposition.
    ///
    /// Budget and tool-error dispositions also mark the group partial. The
    /// disposition is checked against the file tier before it is retained.
    ///
    /// # Errors
    ///
    /// Rejects an invalid policy disposition or an unknown ledger target.
    pub fn set_unread_disposition(
        &mut self,
        path: &RepositoryPath,
        hunk_id: &str,
        disposition: UnreadHunkDisposition,
    ) -> Result<(), CoverageGateError> {
        let file = self
            .ledger
            .files
            .get(path)
            .ok_or(CoverageGateError::Ledger(CoverageError::UnknownFile))?;
        let hunk = file
            .hunks
            .iter()
            .find(|hunk| hunk.hunk_id == hunk_id)
            .ok_or(CoverageGateError::Ledger(CoverageError::UnknownHunk))?;
        validate_disposition(file, hunk.hazardous, &disposition)?;
        match disposition.kind {
            UnreadHunkDispositionKind::BudgetExhausted => {
                self.partial_causes
                    .insert(GroupPartialCause::BudgetExhausted);
            }
            UnreadHunkDispositionKind::ToolError => {
                self.partial_causes.insert(GroupPartialCause::ToolError);
            }
            UnreadHunkDispositionKind::ManifestLowRisk
            | UnreadHunkDispositionKind::RedundantPattern => {}
        }
        self.ledger
            .set_unread_disposition(path, hunk_id, disposition)
            .map_err(CoverageGateError::Ledger)
    }

    /// Record a budget or tool failure independently of unread dispositions.
    pub fn record_partial_cause(&mut self, cause: GroupPartialCause) {
        self.partial_causes.insert(cause);
    }

    /// Terminate the group at the caller's request.
    ///
    /// Completion is the model's voluntary signal, not a requirement this
    /// gate enforces: unread or undispositioned hunks no longer block it,
    /// they are simply not reflected as delivered in the ledger this call
    /// consumes (callers that need that detail for reporting should read
    /// `self.ledger().missing_requirements()` before calling this). Only a
    /// genuine local failure - budget exhaustion or a tool error, recorded as
    /// a disposition by the runtime itself rather than chosen by the model -
    /// still marks the result `Partial` instead of `Complete`.
    #[must_use]
    pub fn complete_group(mut self) -> GroupCompletion {
        self.ledger.finalize_low_risk_deferrals();
        let low_risk_deferrals = count_low_risk_deferrals(&self.ledger);
        if self.partial_causes.is_empty() {
            GroupCompletion::Complete {
                policy_version: GroupCoverageLedger::POLICY_VERSION.to_owned(),
                low_risk_deferrals,
            }
        } else {
            GroupCompletion::Partial {
                policy_version: GroupCoverageLedger::POLICY_VERSION.to_owned(),
                causes: self.partial_causes,
                low_risk_deferrals,
            }
        }
    }
}

fn validate_undelivered_hunk_page(
    ledger: &GroupCoverageLedger,
    path: &RepositoryPath,
    hunk_id: &str,
    page: u32,
) -> Result<(), CoverageGateError> {
    validate_hunk_page(ledger, path, hunk_id, page).map_err(CoverageGateError::Ledger)?;
    let delivered = ledger
        .files
        .get(path)
        .and_then(|file| file.hunks.iter().find(|hunk| hunk.hunk_id == hunk_id))
        .is_some_and(|hunk| hunk.delivered_pages.contains(&page));
    if delivered {
        Err(CoverageGateError::PageAlreadyDelivered)
    } else {
        Ok(())
    }
}

fn validate_hunk_page(
    ledger: &GroupCoverageLedger,
    path: &RepositoryPath,
    hunk_id: &str,
    page: u32,
) -> Result<(), CoverageError> {
    let file = ledger.files.get(path).ok_or(CoverageError::UnknownFile)?;
    let hunk = file
        .hunks
        .iter()
        .find(|hunk| hunk.hunk_id == hunk_id)
        .ok_or(CoverageError::UnknownHunk)?;
    if page == 0 || page > hunk.total_pages {
        return Err(CoverageError::InvalidPage);
    }
    Ok(())
}

fn validate_ledger(
    ledger: &GroupCoverageLedger,
    metadata_only_renames: &BTreeSet<RepositoryPath>,
) -> Result<(), CoverageGateError> {
    if ledger.policy_version != GroupCoverageLedger::POLICY_VERSION {
        return Err(CoverageGateError::PolicyVersion);
    }
    for (path, file) in &ledger.files {
        if path != &file.path {
            return Err(CoverageGateError::FileBinding);
        }
        if file.metadata_only && (!metadata_only_renames.contains(path) || !file.hunks.is_empty()) {
            return Err(CoverageGateError::InvalidMetadataOnlyRename);
        }
        let mut hunk_ids = BTreeSet::new();
        for hunk in &file.hunks {
            if hunk.hunk_id.is_empty()
                || hunk.total_pages == 0
                || hunk
                    .delivered_pages
                    .iter()
                    .any(|page| *page == 0 || *page > hunk.total_pages)
            {
                return Err(CoverageGateError::InvalidHunk);
            }
            if !hunk_ids.insert(hunk.hunk_id.as_str()) {
                return Err(CoverageGateError::DuplicateHunk);
            }
        }
        for (hunk_id, disposition) in &file.unread_dispositions {
            let hunk = file
                .hunks
                .iter()
                .find(|hunk| &hunk.hunk_id == hunk_id)
                .ok_or(CoverageGateError::InvalidDisposition)?;
            validate_disposition(file, hunk.hazardous, disposition)?;
        }
    }
    if metadata_only_renames.iter().any(|path| {
        ledger
            .files
            .get(path)
            .is_none_or(|file| !file.metadata_only)
    }) {
        return Err(CoverageGateError::MetadataRenameNotFound);
    }
    Ok(())
}

fn validate_disposition(
    file: &FileCoverageLedger,
    hazardous: bool,
    disposition: &UnreadHunkDisposition,
) -> Result<(), CoverageGateError> {
    if disposition.note.is_empty()
        || disposition.note.len() > MAX_DISPOSITION_NOTE_BYTES
        || disposition.note.contains('\0')
        || disposition
            .note
            .chars()
            .any(|character| character.is_control() && !matches!(character, '\n' | '\r' | '\t'))
    {
        return Err(CoverageGateError::InvalidDisposition);
    }
    if disposition.kind == UnreadHunkDispositionKind::ManifestLowRisk
        && (file.tier != crate::ReviewValueTier::Low || hazardous)
    {
        return Err(CoverageGateError::InvalidDisposition);
    }
    // A high-risk file or a hazardous hunk requires its body to actually be
    // read; neither shortcut disposition may close it without that read.
    if disposition.kind == UnreadHunkDispositionKind::RedundantPattern
        && (file.tier == crate::ReviewValueTier::High || hazardous)
    {
        return Err(CoverageGateError::InvalidDisposition);
    }
    Ok(())
}

fn disposition_partial_causes(ledger: &GroupCoverageLedger) -> BTreeSet<GroupPartialCause> {
    ledger
        .files
        .values()
        .flat_map(|file| file.unread_dispositions.values())
        .filter_map(|disposition| match disposition.kind {
            UnreadHunkDispositionKind::BudgetExhausted => Some(GroupPartialCause::BudgetExhausted),
            UnreadHunkDispositionKind::ToolError => Some(GroupPartialCause::ToolError),
            UnreadHunkDispositionKind::ManifestLowRisk
            | UnreadHunkDispositionKind::RedundantPattern => None,
        })
        .collect()
}

fn count_low_risk_deferrals(ledger: &GroupCoverageLedger) -> u32 {
    ledger
        .files
        .values()
        .flat_map(|file| file.unread_dispositions.values())
        .filter(|disposition| disposition.kind == UnreadHunkDispositionKind::ManifestLowRisk)
        .count()
        .try_into()
        .unwrap_or(u32::MAX)
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use super::*;
    use crate::{CoverageRequirement, CoverageRequirementKind, HunkCoverage, ReviewValueTier};

    fn path(value: &str) -> RepositoryPath {
        RepositoryPath::try_from(value.to_owned()).expect("path")
    }

    fn hunk(id: &str, pages: u32, hazardous: bool) -> HunkCoverage {
        HunkCoverage {
            hunk_id: id.to_owned(),
            total_pages: pages,
            delivered_pages: BTreeSet::new(),
            hazardous,
        }
    }

    fn file(value: &str, tier: ReviewValueTier, hunks: Vec<HunkCoverage>) -> FileCoverageLedger {
        FileCoverageLedger {
            path: path(value),
            tier,
            manifested: false,
            metadata_only: false,
            hunks,
            unread_dispositions: BTreeMap::new(),
        }
    }

    fn build_gate(file: FileCoverageLedger) -> CoverageCompletionGate {
        CoverageCompletionGate::new(
            GroupCoverageLedger::new([file]).expect("ledger"),
            &BTreeSet::new(),
        )
        .expect("gate")
    }

    fn disposition(kind: UnreadHunkDispositionKind) -> UnreadHunkDisposition {
        UnreadHunkDisposition {
            kind,
            note: "bounded deterministic disposition".to_owned(),
        }
    }

    #[test]
    fn high_risk_requires_every_page_of_every_hunk() {
        let target = path("src/high.rs");
        let mut gate = build_gate(file(
            target.as_str(),
            ReviewValueTier::High,
            vec![hunk("h1", 2, false), hunk("h2", 1, false)],
        ));
        gate.mark_manifested(&target).expect("manifest");
        gate.record_hunk_page(&target, "h1", 1).expect("page");
        let missing = gate.ledger().missing_requirements();
        assert_eq!(missing.len(), 2);
        assert!(
            missing
                .iter()
                .all(|requirement| { requirement.kind == CoverageRequirementKind::HunkBody })
        );
        assert!(matches!(
            gate.complete_group(),
            GroupCompletion::Complete { .. }
        ));

        let mut complete = build_gate(file(
            target.as_str(),
            ReviewValueTier::High,
            vec![hunk("h1", 2, false), hunk("h2", 1, false)],
        ));
        complete.mark_manifested(&target).expect("manifest");
        for (hunk_id, page) in [("h1", 1), ("h1", 2), ("h2", 1)] {
            complete
                .record_hunk_page(&target, hunk_id, page)
                .expect("page");
        }
        assert!(matches!(
            complete.complete_group(),
            GroupCompletion::Complete { .. }
        ));
    }

    #[test]
    fn batched_page_recording_is_atomic() {
        let target = path("src/high.rs");
        let mut gate = build_gate(file(
            target.as_str(),
            ReviewValueTier::High,
            vec![hunk("h1", 1, false)],
        ));
        let error = gate
            .record_hunk_pages(&[
                (target.clone(), "h1".to_owned(), 1),
                (target.clone(), "h1".to_owned(), 2),
            ])
            .expect_err("later invalid page rejects batch");
        assert_eq!(error, CoverageGateError::Ledger(CoverageError::InvalidPage));
        assert!(
            gate.ledger().files[&target].hunks[0]
                .delivered_pages
                .is_empty()
        );
    }

    #[test]
    fn repeated_pages_are_rejected_without_mutating_the_batch() {
        let target = path("src/high.rs");
        let mut gate = build_gate(file(
            target.as_str(),
            ReviewValueTier::High,
            vec![hunk("h1", 2, false)],
        ));
        gate.record_hunk_page(&target, "h1", 1)
            .expect("first delivery");
        assert_eq!(
            gate.record_hunk_page(&target, "h1", 1),
            Err(CoverageGateError::PageAlreadyDelivered)
        );
        assert_eq!(
            gate.record_hunk_pages(&[
                (target.clone(), "h1".to_owned(), 2),
                (target.clone(), "h1".to_owned(), 1),
            ]),
            Err(CoverageGateError::PageAlreadyDelivered)
        );
        assert_eq!(
            gate.ledger().files[&target].hunks[0].delivered_pages,
            BTreeSet::from([1])
        );
    }

    #[test]
    fn standard_requires_a_complete_sample_and_dispositions_for_unread_hunks() {
        let target = path("src/standard.rs");
        let mut gate = build_gate(file(
            target.as_str(),
            ReviewValueTier::Standard,
            vec![hunk("h1", 1, false), hunk("h2", 1, false)],
        ));
        gate.mark_manifested(&target).expect("manifest");
        let missing = gate.ledger().missing_requirements();
        assert!(
            missing
                .iter()
                .any(|requirement| requirement.kind == CoverageRequirementKind::Sample)
        );
        assert!(matches!(
            gate.complete_group(),
            GroupCompletion::Complete { .. }
        ));

        let mut gate = build_gate(file(
            target.as_str(),
            ReviewValueTier::Standard,
            vec![hunk("h1", 1, false), hunk("h2", 1, false)],
        ));
        gate.mark_manifested(&target).expect("manifest");
        gate.record_hunk_page(&target, "h1", 1).expect("sample");
        gate.set_unread_disposition(
            &target,
            "h2",
            disposition(UnreadHunkDispositionKind::RedundantPattern),
        )
        .expect("disposition");
        assert!(matches!(
            gate.complete_group(),
            GroupCompletion::Complete { .. }
        ));
    }

    #[test]
    fn hazardous_hunk_is_promoted_at_standard_and_low_tiers() {
        for tier in [ReviewValueTier::Standard, ReviewValueTier::Low] {
            let target = path("src/promoted.rs");
            let mut gate = build_gate(file(target.as_str(), tier, vec![hunk("hazard", 2, true)]));
            gate.mark_manifested(&target).expect("manifest");
            gate.record_hunk_page(&target, "hazard", 1).expect("page");
            let missing = gate.ledger().missing_requirements();
            let mut expected = Vec::new();
            if tier == ReviewValueTier::Standard {
                expected.push(CoverageRequirement {
                    path: target.clone(),
                    hunk_id: None,
                    kind: CoverageRequirementKind::Sample,
                });
            }
            expected.push(CoverageRequirement {
                path: target,
                hunk_id: Some("hazard".to_owned()),
                kind: CoverageRequirementKind::HunkBody,
            });
            assert_eq!(missing, expected);
            assert!(matches!(
                gate.complete_group(),
                GroupCompletion::Complete { .. }
            ));
        }
    }

    #[test]
    fn low_risk_manifest_deferral_is_policy_complete() {
        let target = path("docs/guide.md");
        let mut gate = build_gate(file(
            target.as_str(),
            ReviewValueTier::Low,
            vec![hunk("h1", 2, false), hunk("h2", 1, false)],
        ));
        gate.mark_manifested(&target).expect("manifest");
        assert_eq!(
            gate.complete_group(),
            GroupCompletion::Complete {
                policy_version: GroupCoverageLedger::POLICY_VERSION.to_owned(),
                low_risk_deferrals: 2,
            }
        );
    }

    #[test]
    fn metadata_only_rename_completes_from_manifest() {
        let target = path("src/renamed.rs");
        let mut metadata = file(target.as_str(), ReviewValueTier::Standard, Vec::new());
        metadata.metadata_only = true;
        let mut gate = CoverageCompletionGate::new(
            GroupCoverageLedger::new([metadata.clone()]).expect("ledger"),
            &BTreeSet::from([target.clone()]),
        )
        .expect("trusted rename");
        gate.mark_manifested(&target).expect("manifest");
        assert!(matches!(
            gate.complete_group(),
            GroupCompletion::Complete { .. }
        ));
        assert_eq!(
            CoverageCompletionGate::new(
                GroupCoverageLedger::new([metadata]).expect("ledger"),
                &BTreeSet::new(),
            )
            .err(),
            Some(CoverageGateError::InvalidMetadataOnlyRename)
        );
    }

    #[test]
    fn exact_missing_manifest_requirement_is_returned() {
        let target = path("src/unread.rs");
        let gate = build_gate(file(
            target.as_str(),
            ReviewValueTier::Standard,
            vec![hunk("h1", 1, false)],
        ));
        assert_eq!(
            gate.ledger().missing_requirements(),
            vec![CoverageRequirement {
                path: target,
                hunk_id: None,
                kind: CoverageRequirementKind::Manifest,
            }]
        );
        assert!(matches!(
            gate.complete_group(),
            GroupCompletion::Complete { .. }
        ));
    }

    #[test]
    fn budget_or_tool_failure_makes_policy_complete_group_partial() {
        for cause in [
            GroupPartialCause::BudgetExhausted,
            GroupPartialCause::ToolError,
        ] {
            let target = path("src/complete.rs");
            let mut gate = build_gate(file(
                target.as_str(),
                ReviewValueTier::High,
                vec![hunk("h1", 1, false)],
            ));
            gate.mark_manifested(&target).expect("manifest");
            gate.record_hunk_page(&target, "h1", 1).expect("page");
            gate.record_partial_cause(cause);
            assert!(matches!(
                gate.complete_group(),
                GroupCompletion::Partial { causes, .. } if causes == BTreeSet::from([cause])
            ));
        }
    }

    #[test]
    fn budget_disposition_records_partial_and_missing_requirements() {
        let target = path("src/partial.rs");
        let mut gate = build_gate(file(
            target.as_str(),
            ReviewValueTier::Standard,
            vec![hunk("h1", 1, false), hunk("h2", 1, false)],
        ));
        gate.mark_manifested(&target).expect("manifest");
        gate.set_unread_disposition(
            &target,
            "h2",
            disposition(UnreadHunkDispositionKind::BudgetExhausted),
        )
        .expect("disposition");
        let missing = gate.ledger().missing_requirements();
        let completion = gate.complete_group();
        let GroupCompletion::Partial { causes, .. } = completion else {
            panic!("expected partial completion, got {completion:?}");
        };
        assert!(causes.contains(&GroupPartialCause::BudgetExhausted));
        assert!(
            missing
                .iter()
                .any(|requirement| requirement.kind == CoverageRequirementKind::Sample)
        );
    }

    #[test]
    fn manifest_low_risk_cannot_be_forged_for_standard_or_hazardous_hunks() {
        for (tier, hazardous) in [
            (ReviewValueTier::Standard, false),
            (ReviewValueTier::Low, true),
        ] {
            let target = path("src/forged.rs");
            let mut gate = build_gate(file(target.as_str(), tier, vec![hunk("h1", 1, hazardous)]));
            gate.mark_manifested(&target).expect("manifest");
            assert_eq!(
                gate.set_unread_disposition(
                    &target,
                    "h1",
                    disposition(UnreadHunkDispositionKind::ManifestLowRisk),
                ),
                Err(CoverageGateError::InvalidDisposition)
            );
        }
    }

    #[test]
    fn forged_policy_or_file_binding_is_rejected() {
        let target = path("src/forged.rs");
        let mut ledger =
            GroupCoverageLedger::new([file(target.as_str(), ReviewValueTier::Low, Vec::new())])
                .expect("ledger");
        ledger.policy_version = "forged".to_owned();
        assert_eq!(
            CoverageCompletionGate::new(ledger, &BTreeSet::new()).err(),
            Some(CoverageGateError::PolicyVersion)
        );

        let mut ledger =
            GroupCoverageLedger::new([file(target.as_str(), ReviewValueTier::Low, Vec::new())])
                .expect("ledger");
        ledger.files.get_mut(&target).expect("file").path = path("src/other.rs");
        assert_eq!(
            CoverageCompletionGate::new(ledger, &BTreeSet::new()).err(),
            Some(CoverageGateError::FileBinding)
        );
    }
}
