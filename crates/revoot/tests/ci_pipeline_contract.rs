use std::fs;
use std::path::{Path, PathBuf};

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("revoot crate must live below the workspace root")
        .to_owned()
}

#[test]
fn github_ci_is_the_canonical_pull_request_gate() {
    let root = workspace_root();
    let pipeline = fs::read_to_string(root.join(".github/workflows/ci.yml"))
        .expect("canonical GitHub pipeline must be readable");
    let _: serde_json::Value =
        serde_saphyr::from_str(&pipeline).expect("GitHub pipeline must be valid YAML");

    assert_eq!(pipeline.matches("mise run verify").count(), 1);
    assert!(pipeline.contains("pull_request:"));
    assert!(pipeline.contains("branches:\n      - main"));
    assert!(pipeline.contains("contents: read"));
    assert!(pipeline.contains("persist-credentials: false"));
    assert!(pipeline.contains("workflow_dispatch:"));
    assert!(!pipeline.contains("pull_request_target"));
    assert!(!pipeline.contains("contents: write"));
    assert!(!pipeline.contains("packages: write"));
    assert!(!root.join(".gitlab-ci.yml").exists());
}

#[test]
fn github_release_owns_archives_and_the_single_public_image() {
    let pipeline = fs::read_to_string(workspace_root().join(".github/workflows/release.yml"))
        .expect("release workflow must be readable");
    let _: serde_json::Value =
        serde_saphyr::from_str(&pipeline).expect("release workflow must be valid YAML");

    assert!(pipeline.contains("mise run package:linux"));
    assert!(pipeline.contains("mise run package:macos"));
    assert!(pipeline.contains("ghcr.io/${{ github.repository }}"));
    assert!(pipeline.contains("packages: write"));
    assert!(pipeline.contains("contents: write"));
    assert!(pipeline.contains("docker buildx imagetools create"));
    assert!(pipeline.contains("gh release create"));
    assert!(pipeline.contains("actions/attest@59d89421af93a897026c735860bf21b6eb4f7b26"));
    assert!(pipeline.contains("revoot.cdx.json"));
    assert!(pipeline.contains("subject-checksums: dist/SHA256SUMS"));
    assert!(!pipeline.contains("registry.gitlab.com"));
}

#[test]
fn gitlab_is_a_component_fixture_not_a_source_mirror() {
    let root = workspace_root();
    let template = fs::read_to_string(root.join("ci/gitlab/components/review/template.yml"))
        .expect("GitLab component must be readable");
    let documentation = fs::read_to_string(root.join("docs/operations/gitlab-component.md"))
        .expect("GitLab component policy must be readable");

    assert!(template.contains("@sha256:[0-9a-f]{64}"));
    assert!(!template.contains("default: ghcr.io/getrevoot/revoot:"));
    assert!(template.contains("default: .post"));
    assert!(template.contains("needs: $[[ inputs.needs ]]"));
    assert!(
        template.contains("CI_MERGE_REQUEST_SOURCE_PROJECT_ID == $CI_MERGE_REQUEST_PROJECT_ID")
    );
    assert!(!template.contains("CI_MERGE_REQUEST_TARGET_PROJECT_ID"));
    assert!(!template.contains("registry.gitlab.com/revoot"));
    assert!(documentation.contains("not a mirror"));
    assert!(documentation.contains("GitHub remains authoritative"));
    assert!(
        !root
            .join("docs/operations/repository-mirroring.md")
            .exists()
    );
}
