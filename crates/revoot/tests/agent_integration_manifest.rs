use std::process::Command;

use serde_json::Value;

#[test]
fn delegate_manifest_is_canonical_and_requires_no_repository_or_provider() {
    let directory = tempfile::tempdir().expect("temporary non-repository directory");
    let output = Command::new(env!("CARGO_BIN_EXE_revoot"))
        .args(["delegate", "manifest"])
        .current_dir(directory.path())
        .env_clear()
        .env("REVOOT_PROVIDER", "unsupported-provider")
        .env("OPENAI_API_KEY", "must-not-appear")
        .env("ANTHROPIC_API_KEY", "must-not-appear")
        .output()
        .expect("delegate manifest command");
    assert!(
        output.status.success(),
        "delegate manifest failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());

    let value: Value = serde_json::from_slice(&output.stdout).expect("manifest JSON");
    assert_eq!(value["schema_version"], "revoot.agent-integration/v1");
    assert_eq!(value["executable"], "revoot");
    assert_eq!(value["mcp"]["transport"], "stdio");
    assert_eq!(
        value["cli_workflows"][0]["arguments"],
        serde_json::json!(["delegate", "manifest"])
    );
    let authority = value["authority"].as_object().expect("authority object");
    assert!(authority.values().all(|state| state == "denied"));

    let text = String::from_utf8(output.stdout).expect("UTF-8 manifest");
    for forbidden in [
        "must-not-appear",
        "install_command",
        "code_edit",
        "api_key",
        "provider_key",
    ] {
        assert!(!text.contains(forbidden));
    }
}
