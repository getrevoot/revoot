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
fn linux_archive_verification_uses_portable_numeric_ownership() {
    let verifier = fs::read_to_string(workspace().join("scripts/verify-linux-artifacts.sh"))
        .expect("Linux artifact verifier");

    assert!(verifier.contains("tar --numeric-owner -tvzf"));
    assert!(verifier.contains("$2 ~ /^[0-9]+\\/[0-9]+$/"));
    assert!(verifier.contains("$3 ~ /^[0-9]+$/ && $4 ~ /^[0-9]+$/"));
    assert!(verifier.contains("-rwxr-xr-x 0 0 revoot"));
    assert!(!verifier.contains("*root*root*"));
}

#[test]
fn workspace_path_dependencies_remain_packageable() {
    let manifest = fs::read_to_string(workspace().join("Cargo.toml")).expect("workspace manifest");
    let dependency = manifest
        .lines()
        .find(|line| line.starts_with("revoot-core = "))
        .expect("revoot-core workspace dependency");

    assert!(dependency.contains("version = \""));
    assert!(dependency.contains("path = \"crates/revoot-core\""));

    let task_file = fs::read_to_string(workspace().join("mise.toml")).expect("mise tasks");
    assert!(task_file.contains("bash scripts/run-release-plz.sh release-pr"));

    let cargo_wrapper = fs::read_to_string(workspace().join("scripts/release-plz-cargo.sh"))
        .expect("Cargo wrapper");
    assert!(cargo_wrapper.contains("${1:-} == package"));
    assert!(cargo_wrapper.contains("--allow-dirty) allow_dirty=true"));
    assert!(cargo_wrapper.contains("--workspace) workspace=true"));
    assert!(cargo_wrapper.contains("--no-verify"));
    assert!(cargo_wrapper.contains("publish.workspace = true"));
    assert!(cargo_wrapper.contains("print \"publish = true\""));
    assert!(cargo_wrapper.contains("revoot-core = { path = "));
    assert!(cargo_wrapper.contains("workspace_version=$(awk"));
    assert!(cargo_wrapper.contains("trap restore_manifests EXIT HUP INT TERM"));
    assert!(cargo_wrapper.contains("archives=(\"$package_root\"/*.crate)"));
    assert!(cargo_wrapper.contains("tar -xzf \"$archive\" -C \"$package_root\""));
    assert!(cargo_wrapper.contains("exec \"$real_cargo\" \"$@\""));
}

#[test]
fn release_preparation_is_manual_and_updates_a_pull_request() {
    let root = workspace();
    let pipeline = fs::read_to_string(root.join(".github/workflows/prepare-release.yml"))
        .expect("release preparation pipeline");
    let _: serde_json::Value =
        serde_saphyr::from_str(&pipeline).expect("release preparation pipeline must be valid YAML");

    assert!(pipeline.contains("workflow_dispatch:"));
    assert!(pipeline.contains("actions/create-github-app-token@"));
    assert!(pipeline.contains("secrets.RELEASE_APP_ID"));
    assert!(pipeline.contains("secrets.RELEASE_APP_PRIVATE_KEY"));
    assert!(pipeline.contains("mise run release:pr"));
    assert!(pipeline.contains("GIT_TOKEN: ${{ steps.release-token.outputs.token }}"));
    assert!(!pipeline.contains("RELEASE_PLZ_TOKEN"));
    assert!(!pipeline.contains("github.token"));
}

#[test]
fn merged_release_pull_requests_are_tagged_by_the_release_app() {
    let root = workspace();
    let pipeline = fs::read_to_string(root.join(".github/workflows/promote-release.yml"))
        .expect("release promotion pipeline");
    let _: serde_json::Value =
        serde_saphyr::from_str(&pipeline).expect("release promotion pipeline must be valid YAML");

    assert!(pipeline.contains("pull_request:"));
    assert!(pipeline.contains("types: [closed]"));
    assert!(pipeline.contains("workflow_dispatch:"));
    assert!(pipeline.contains("release_pr:"));
    assert!(pipeline.contains("cancel-in-progress: false"));
    assert!(pipeline.contains("actions/create-github-app-token@"));
    assert!(pipeline.contains("secrets.RELEASE_APP_ID"));
    assert!(pipeline.contains("secrets.RELEASE_APP_PRIVATE_KEY"));
    assert!(pipeline.contains(".merged_at != null"));
    assert!(pipeline.contains(".base.ref == \"main\""));
    assert!(pipeline.contains("startsWith(github.event.pull_request.head.ref, 'release-plz-')"));
    assert!(pipeline.contains("persist-credentials: true"));
    assert!(pipeline.contains("path: release-automation"));
    assert!(pipeline.contains("path: release-source"));
    assert!(pipeline.contains("release-automation/scripts/tag-merged-release.sh"));
    assert!(!pipeline.contains("github.token"));

    let tagger =
        fs::read_to_string(root.join("scripts/tag-merged-release.sh")).expect("release tagger");
    assert!(tagger.contains("merge-base --is-ancestor"));
    assert!(tagger.contains("chore: release $tag"));
    assert!(tagger.contains("show-ref --verify --quiet"));
    assert!(tagger.contains("tag -a \"$tag\" \"$release_sha\""));
    assert!(tagger.contains("push origin \"refs/tags/$tag\""));
}

#[test]
fn pull_request_dogfooding_publishes_and_cleans_up_scoped_images() {
    let root = workspace();
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

    let cleanup_pipeline = fs::read_to_string(root.join(".github/workflows/cleanup-pr-images.yml"))
        .expect("pull request image cleanup pipeline");
    let _: serde_json::Value = serde_saphyr::from_str(&cleanup_pipeline)
        .expect("pull request image cleanup pipeline must be valid YAML");

    assert!(cleanup_pipeline.contains("pull_request_target:"));
    assert!(cleanup_pipeline.contains("types: [closed]"));
    assert!(cleanup_pipeline.contains("schedule:"));
    assert!(cleanup_pipeline.contains("workflow_dispatch:"));
    assert!(cleanup_pipeline.contains("packages: write"));
    assert!(cleanup_pipeline.contains("pull-requests: read"));
    assert!(cleanup_pipeline.contains("format('revoot-{0}'"));
    assert!(cleanup_pipeline.contains("^pr-[0-9]+$"));
    assert!(cleanup_pipeline.contains(".metadata.container.tags | join(\",\")"));
    assert!(cleanup_pipeline.contains("IFS=',' read -ra version_tags"));
    assert!(cleanup_pipeline.contains("for tag in \"${version_tags[@]}\""));
    assert!(cleanup_pipeline.contains("[[ ! \"$tag\" =~ ^pr-[0-9]+$ ]]"));
    assert!(cleanup_pipeline.contains("gh api --method DELETE"));
    assert!(!cleanup_pipeline.contains("actions/checkout"));
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
        &["config", "commit.gpgSign", "false"][..],
        &["config", "tag.gpgSign", "false"][..],
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

#[test]
fn merged_release_tagger_is_validated_and_idempotent() {
    let root = workspace();
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock")
        .as_nanos();
    let fixture = std::env::temp_dir().join(format!("revoot-release-tagger-{nonce}"));
    let remote = std::env::temp_dir().join(format!("revoot-release-origin-{nonce}.git"));
    fs::create_dir_all(&fixture).expect("release tagger fixture directory");
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
        &["init", "-b", "main"][..],
        &["config", "user.name", "Revoot Test"][..],
        &["config", "user.email", "test@example.invalid"][..],
        &["config", "commit.gpgSign", "false"][..],
        &["config", "tag.gpgSign", "false"][..],
        &["add", "."][..],
        &["commit", "-m", "chore: release v0.1.0"][..],
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
    assert!(
        Command::new("git")
            .args(["init", "--bare", remote.to_str().expect("remote path")])
            .status()
            .expect("bare remote")
            .success()
    );
    assert!(
        Command::new("git")
            .args([
                "remote",
                "add",
                "origin",
                remote.to_str().expect("remote path")
            ])
            .current_dir(&fixture)
            .status()
            .expect("add fixture remote")
            .success()
    );
    assert!(
        Command::new("git")
            .args(["push", "--set-upstream", "origin", "main"])
            .current_dir(&fixture)
            .status()
            .expect("push fixture main")
            .success()
    );

    let release_sha = String::from_utf8(
        Command::new("git")
            .args(["rev-parse", "HEAD"])
            .current_dir(&fixture)
            .output()
            .expect("fixture release SHA")
            .stdout,
    )
    .expect("UTF-8 release SHA");
    let release_sha = release_sha.trim();
    for _ in 0..2 {
        assert!(
            Command::new("bash")
                .arg(root.join("scripts/tag-merged-release.sh"))
                .args([release_sha, fixture.to_str().expect("fixture path")])
                .status()
                .expect("merged release tagger")
                .success()
        );
    }

    let remote_tag = String::from_utf8(
        Command::new("git")
            .args([
                "--git-dir",
                remote.to_str().expect("remote path"),
                "rev-parse",
                "v0.1.0^{commit}",
            ])
            .output()
            .expect("remote release tag")
            .stdout,
    )
    .expect("UTF-8 remote tag");
    assert_eq!(remote_tag.trim(), release_sha);

    fs::remove_dir_all(fixture).expect("remove release tagger fixture");
    fs::remove_dir_all(remote).expect("remove release tagger remote");
}
