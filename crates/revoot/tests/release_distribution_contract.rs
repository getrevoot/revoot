use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

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
    assert!(!pipeline.contains("package-manager"));
    assert!(!pipeline.contains("revoot.mise.toml"));
    assert!(!pipeline.contains("revoot.rb"));
    assert!(pipeline.contains("ghcr.io/${{ github.repository }}"));
    assert!(pipeline.contains("gh release create \"$GITHUB_REF_NAME\""));
    assert!(pipeline.contains("--verify-tag --generate-notes"));
}

#[test]
fn readme_leads_with_the_versioned_container_image() {
    let root = workspace();
    let readme = fs::read_to_string(root.join("README.md")).expect("README");
    let docker = readme
        .find("## Run with Docker")
        .expect("Docker quickstart");
    let development = readme.find("## Development").expect("development section");

    assert!(docker < development);
    assert!(readme.contains("ghcr.io/getrevoot/revoot:0.1.0 review"));
    assert!(readme.contains("$PWD:/workspace:ro"));
    assert!(!readme.contains("mise use --global"));
}

#[test]
fn release_version_guard_binds_tag_and_generated_assets() {
    let root = workspace();
    let matching = Command::new("bash")
        .arg("scripts/check-release-version.sh")
        .env("MISE_PROJECT_ROOT", &root)
        .env("GITHUB_REF_NAME", "v0.1.0")
        .current_dir(&root)
        .status()
        .expect("release version guard");
    assert!(matching.success());

    let mismatch = Command::new("bash")
        .arg("scripts/check-release-version.sh")
        .env("MISE_PROJECT_ROOT", &root)
        .env("GITHUB_REF_NAME", "v0.2.0")
        .current_dir(&root)
        .status()
        .expect("release version mismatch");
    assert!(!mismatch.success());
}
