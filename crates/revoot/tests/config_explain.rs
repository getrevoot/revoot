use std::process::Command;

#[test]
fn config_explain_reports_structured_repository_policy() {
    let root = std::env::temp_dir().join(format!("revoot-config-explain-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir(&root).unwrap();
    let path = root.join(".revoot.toml");
    std::fs::write(
        &path,
        r#"version = 1
[repository]
guidance = "Writes must be idempotent."
[[rules]]
paths = ["src/**"]
focus = ["correctness"]
guidance = "Validate transaction boundaries."
[[suppressions]]
fingerprint = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
reason = "Tracked false positive."
expires = "2099-12-31"
"#,
    )
    .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_revoot"))
        .args([
            "config",
            "explain",
            "--json",
            "--base-config",
            path.to_str().unwrap(),
        ])
        .env_clear()
        .output()
        .unwrap();
    assert!(output.status.success());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["repository"]["rules"][0]["paths"][0], "src/**");
    assert_eq!(
        report["repository"]["suppressions"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert!(!String::from_utf8_lossy(&output.stdout).contains("provider ="));
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn config_explain_json_is_deterministic_secretless_and_policy_constrained() {
    let output = Command::new(env!("CARGO_BIN_EXE_revoot"))
        .args(["config", "explain", "--json", "--context-lines", "300"])
        .env_clear()
        .env(
            "REVOOT_GITLAB_TOKEN_FILE",
            "/definitely/not-opened-by-config-explain",
        )
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !output
            .stdout
            .windows(20)
            .any(|bytes| bytes == b"not-opened-by-config")
    );

    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["schema_version"], "revoot.config-explain/v2");
    assert_eq!(report["credentials_loaded"], false);
    assert_eq!(report["repository"]["rules"], serde_json::json!([]));
    let fields = report["fields"].as_array().unwrap();
    assert!(
        fields
            .windows(2)
            .all(|rows| rows[0]["key"].as_str() < rows[1]["key"].as_str())
    );
    let context = fields
        .iter()
        .find(|field| field["key"] == "review.context_lines")
        .unwrap();
    assert_eq!(context["requested"]["value"]["value"], 300);
    assert_eq!(context["requested"]["provenance"]["source"], "command_line");
    assert_eq!(context["effective"]["value"], 200);
    assert_eq!(context["constrained"], true);
}

#[test]
fn doctor_command_remains_available() {
    let output = Command::new(env!("CARGO_BIN_EXE_revoot"))
        .args(["doctor", "--json"])
        .env_clear()
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["schema_version"], "revoot.doctor/v3");
    assert_eq!(
        report["capabilities"]["architecture"],
        "in-process-rust-agent"
    );
    assert_eq!(report["capabilities"]["review_available"], true);
    assert_eq!(
        report["capabilities"]["publication_adapters"],
        serde_json::json!(["gitlab", "github"])
    );
}
