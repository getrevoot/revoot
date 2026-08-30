use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

static SEQUENCE: AtomicU64 = AtomicU64::new(1);

struct OutputDirectory(PathBuf);

impl OutputDirectory {
    fn create() -> Self {
        let sequence = SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "revoot-release-contract-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&path).expect("output directory");
        Self(path)
    }
}

impl Drop for OutputDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn workspace() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace")
        .to_owned()
}

#[test]
fn package_manager_manifests_are_pinned_and_portable() {
    let root = workspace();
    let output = OutputDirectory::create();
    let checksums = output.0.join("SHA256SUMS");
    fs::write(
        &checksums,
        format!(
            "{}  revoot-linux-amd64.tar.gz\n{}  revoot-linux-arm64.tar.gz\n{}  revoot-macos-arm64.tar.gz\n",
            "a".repeat(64),
            "b".repeat(64),
            "c".repeat(64)
        ),
    )
    .expect("checksum fixture");
    let status = Command::new("bash")
        .arg("scripts/generate-package-manager-manifests.sh")
        .arg("0.1.0")
        .arg(&output.0)
        .env("REVOOT_CHECKSUM_FILE", &checksums)
        .current_dir(&root)
        .status()
        .expect("manifest generator");
    assert!(status.success());

    let mise = fs::read_to_string(output.0.join("revoot.mise.toml")).expect("mise manifest");
    assert!(mise.contains("github:getrevoot/revoot"));
    assert!(mise.contains("linux-x64"));
    assert!(mise.contains("linux-arm64"));
    assert!(mise.contains("macos-arm64"));
    assert_eq!(mise.matches("sha256:").count(), 3);
    assert!(!mise.contains("latest"));
    assert!(!mise.contains("ubi:"));

    let formula = fs::read_to_string(output.0.join("revoot.rb")).expect("formula");
    assert!(formula.contains("license \"Apache-2.0\""));
    assert!(formula.contains("bash_completion.install"));
    assert!(formula.contains("zsh_completion.install"));
    assert!(formula.contains("fish_completion.install"));
    assert_eq!(formula.matches("sha256 \"").count(), 3);

    let rejected = Command::new("bash")
        .arg("scripts/generate-package-manager-manifests.sh")
        .arg("not-a-version")
        .arg(&output.0)
        .env("REVOOT_CHECKSUM_FILE", checksums)
        .current_dir(root)
        .status()
        .expect("version rejection");
    assert!(!rejected.success());
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
    assert!(pipeline.contains("ghcr.io/${{ github.repository }}"));
    assert!(pipeline.contains("gh release create \"$GITHUB_REF_NAME\""));
    assert!(pipeline.contains("--verify-tag --generate-notes"));
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
