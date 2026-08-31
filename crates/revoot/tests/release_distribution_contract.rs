use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn workspace() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace")
        .to_owned()
}

#[test]
fn release_workflow_builds_packages_images_and_checksums() {
    let root = workspace();
    let pipeline =
        fs::read_to_string(root.join(".github/workflows/release.yml")).expect("release pipeline");
    assert!(pipeline.contains("packages: write"));
    assert!(pipeline.contains("contents: write"));
    assert!(pipeline.contains("mise run release:version"));
    assert!(pipeline.contains("mise run package:linux"));
    assert!(pipeline.contains("mise run package:macos"));
    assert!(pipeline.contains("mise run release:checksums"));
    assert!(pipeline.contains("mise run release:notes"));
    assert!(pipeline.contains("mise run sbom"));
    assert!(pipeline.contains("actions/attest@59d89421af93a897026c735860bf21b6eb4f7b26"));
    assert!(!pipeline.contains("package-manager"));
    assert!(!pipeline.contains("revoot.mise.toml"));
    assert!(!pipeline.contains("revoot.rb"));
    assert!(pipeline.contains("ghcr.io/${{ github.repository }}"));
    assert!(pipeline.contains("gh release create \"$GITHUB_REF_NAME\""));
    assert!(pipeline.contains("gh release edit \"$GITHUB_REF_NAME\" --notes-file"));
    assert!(pipeline.contains("--verify-tag --notes-file dist/release-notes.md"));
    assert!(!pipeline.contains("--generate-notes"));
}

#[test]
fn release_preparation_is_manual_and_updates_a_pull_request() {
    let root = workspace();
    let pipeline = fs::read_to_string(root.join(".github/workflows/prepare-release.yml"))
        .expect("release preparation pipeline");
    let _: serde_json::Value =
        serde_saphyr::from_str(&pipeline).expect("release preparation pipeline must be valid YAML");

    assert!(pipeline.contains("workflow_dispatch:"));
    assert!(pipeline.contains("contents: write"));
    assert!(pipeline.contains("pull-requests: write"));
    assert!(pipeline.contains("mise run release:pr"));
    assert!(pipeline.contains("GIT_TOKEN: ${{ secrets.RELEASE_PLZ_TOKEN || github.token }}"));
}

#[test]
fn preview_workflow_publishes_green_main_and_manual_images_for_dogfooding() {
    let root = workspace();
    let pipeline = fs::read_to_string(root.join(".github/workflows/preview-image.yml"))
        .expect("preview pipeline");
    let _: serde_json::Value =
        serde_saphyr::from_str(&pipeline).expect("preview pipeline must be valid YAML");

    assert!(pipeline.contains("workflow_dispatch:"));
    assert!(pipeline.contains("workflow_run:"));
    assert!(pipeline.contains("github.event.workflow_run.conclusion == 'success'"));
    assert!(pipeline.contains("github.event.workflow_run.event == 'push'"));
    assert!(pipeline.contains("github.event.workflow_run.head_branch == 'main'"));
    assert!(pipeline.contains("head_repository.full_name == github.repository"));
    assert!(pipeline.contains("packages: write"));
    assert!(pipeline.contains("package:linux:release:amd64"));
    assert!(pipeline.contains("tag=main"));
    assert!(pipeline.contains("sha_tag=sha-${SOURCE_SHA:0:12}"));
    assert!(pipeline.contains("docker push \"$IMAGE:$PREVIEW_TAG\""));
    assert!(pipeline.contains("docker push \"$IMAGE:$SHA_TAG\""));
    assert!(!pipeline.contains("gh release create"));

    let review_pipeline =
        fs::read_to_string(root.join(".github/workflows/revoot.yml")).expect("review pipeline");
    assert!(review_pipeline.contains("mise run package:linux:release:amd64"));
    assert!(review_pipeline.contains("docker push \"$IMAGE\""));
    assert!(review_pipeline.contains(
        "image: ghcr.io/${{ github.repository }}:pr-${{ github.event.pull_request.number }}"
    ));
    assert!(review_pipeline.contains("needs: publish-image"));
    let checkout = review_pipeline
        .find("Check out image definition")
        .expect("image definition checkout");
    let download = review_pipeline
        .find("Download binary")
        .expect("binary artifact download");
    assert!(checkout < download);
    assert!(!review_pipeline.contains("vars.REVOOT_IMAGE"));
}

#[test]
fn readme_prioritizes_ci_and_documents_distributions() {
    let root = workspace();
    let readme = fs::read_to_string(root.join("README.md")).expect("README");
    let ci = readme
        .find("## Add Revoot to Your CI")
        .expect("CI quickstart");
    let local = readme
        .find("## Running Revoot locally")
        .expect("local usage section");
    let development = readme.find("## Development").expect("development section");

    assert!(ci < local);
    assert!(local < development);
    assert!(readme.contains("ghcr.io/getrevoot/revoot:VERSION@sha256:DIGEST"));
    assert!(readme.contains("$PWD:/workspace:ro"));
    assert!(readme.contains("https://github.com/getrevoot/revoot/releases"));
    assert!(readme.contains("revoot-linux-amd64.tar.gz"));
    assert!(readme.contains("revoot-linux-arm64.tar.gz"));
    assert!(readme.contains("revoot-macos-arm64.tar.gz"));
    assert!(readme.contains("SHA256SUMS"));
    assert!(readme.contains("CycloneDX SBOM"));
    assert!(readme.contains("docs/security.md"));
    assert!(readme.contains("logo.svg"));
    assert!(!readme.contains("logo-dark.svg"));
    assert!(!readme.contains("mise use --global"));
}

#[test]
fn release_version_guard_binds_tag_package_and_changelog() {
    let root = workspace();
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock")
        .as_nanos();
    let fixture = std::env::temp_dir().join(format!("revoot-release-guard-{nonce}"));
    fs::create_dir_all(&fixture).expect("release fixture directory");
    fs::write(
        fixture.join("Cargo.toml"),
        "[workspace.package]\nversion = \"0.1.0\"\n",
    )
    .expect("Cargo fixture");
    fs::write(
        fixture.join("CHANGELOG.md"),
        "# Changelog\n\n## [Unreleased]\n\n## [0.1.0](https://example.invalid/v0.1.0) - 2026-08-30\n\n- Initial release.\n",
    )
    .expect("changelog fixture");
    for arguments in [
        &["init"][..],
        &["config", "user.name", "Revoot Test"][..],
        &["config", "user.email", "test@example.invalid"][..],
        &["add", "."][..],
        &["commit", "-m", "test: release fixture"][..],
        &["tag", "-a", "v0.1.0", "-m", "Revoot v0.1.0"][..],
    ] {
        assert!(
            Command::new("git")
                .args(arguments)
                .current_dir(&fixture)
                .status()
                .expect("git fixture command")
                .success()
        );
    }

    let matching = Command::new("bash")
        .arg(root.join("scripts/check-release-version.sh"))
        .env("MISE_PROJECT_ROOT", &fixture)
        .env("GITHUB_REF_NAME", "v0.1.0")
        .current_dir(&fixture)
        .status()
        .expect("release version guard");
    assert!(matching.success());

    let mismatch = Command::new("bash")
        .arg(root.join("scripts/check-release-version.sh"))
        .env("MISE_PROJECT_ROOT", &fixture)
        .env("GITHUB_REF_NAME", "v0.2.0")
        .current_dir(&fixture)
        .status()
        .expect("release version mismatch");
    assert!(!mismatch.success());

    fs::remove_dir_all(fixture).expect("remove release fixture");
}
