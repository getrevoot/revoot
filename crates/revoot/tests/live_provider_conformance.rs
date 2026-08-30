//! Credentialed provider smoke tests.
//!
//! These tests are ignored by the default suite because they make billable
//! network requests. The dedicated mise task requires explicit credentials and
//! model IDs; a missing input fails rather than producing false-green evidence.

use revoot::egress_setup::authorize_standard_provider;
use revoot::providers::ApiKey;
use revoot::providers::anthropic::{AnthropicAdapter, AnthropicConfig};
use revoot::providers::openai::{OpenAiAdapter, OpenAiConfig};
use revoot_core::provider::{
    CancellationToken, ModelContent, ModelFinishReason, ModelMessage, ModelRequest, ModelRole,
    ModelTool, ProviderAdapter,
};

fn credential(name: &str) -> Vec<u8> {
    std::env::var_os(name)
        .unwrap_or_else(|| panic!("{name} is required for live conformance"))
        .into_encoded_bytes()
}

fn model(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} is required for live conformance"))
}

fn request(model: String) -> ModelRequest {
    ModelRequest {
        model,
        system: Some("Follow the exact tool instruction, then answer after the result.".to_owned()),
        messages: vec![ModelMessage {
            role: ModelRole::User,
            content: vec![ModelContent::Text {
                text: "Call revoot_probe exactly once with value revoot.".to_owned(),
            }],
        }],
        tools: vec![ModelTool {
            name: "revoot_probe".to_owned(),
            description: "Return one live conformance probe.".to_owned(),
            input_schema: serde_json::json!({
                "type": "object",
                "additionalProperties": false,
                "required": ["value"],
                "properties": {"value": {"const": "revoot"}}
            }),
        }],
        max_output_tokens: 128,
        temperature: None,
    }
}

async fn assert_tool_round_trip(adapter: &dyn ProviderAdapter, model: String) {
    let cancellation = CancellationToken::default();
    let initial = request(model);
    let response = adapter
        .complete(&initial, &cancellation)
        .await
        .expect("live tool-call response");
    assert!(!response.model.is_empty());
    assert!(!response.content.is_empty());
    assert!(response.usage.input_tokens > 0);
    assert!(response.usage.output_tokens > 0);
    assert_eq!(response.finish_reason, ModelFinishReason::ToolUse);
    let calls = response
        .content
        .iter()
        .filter_map(|content| match content {
            ModelContent::ToolUse { id, name, input } => {
                Some((id.clone(), name.clone(), input.clone()))
            }
            ModelContent::Text { .. } | ModelContent::ToolResult { .. } => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].1, "revoot_probe");
    assert_eq!(calls[0].2["value"], "revoot");

    let mut follow_up = initial;
    follow_up.messages.push(ModelMessage {
        role: ModelRole::Assistant,
        content: response.content,
    });
    follow_up.messages.push(ModelMessage {
        role: ModelRole::User,
        content: vec![ModelContent::ToolResult {
            tool_use_id: calls[0].0.clone(),
            content: r#"{"ok":true}"#.to_owned(),
            is_error: false,
        }],
    });
    let final_response = adapter
        .complete(&follow_up, &cancellation)
        .await
        .expect("live post-tool response");
    assert!(!final_response.model.is_empty());
    assert!(
        final_response
            .content
            .iter()
            .any(|content| matches!(content, ModelContent::Text { text } if !text.is_empty()))
    );
    assert!(final_response.usage.input_tokens > 0);
    assert!(final_response.usage.output_tokens > 0);
}

#[tokio::test]
#[ignore = "requires ANTHROPIC_API_KEY and REVOOT_LIVE_ANTHROPIC_MODEL"]
async fn anthropic_live_contract() {
    let authorization =
        authorize_standard_provider("anthropic", "https://api.anthropic.com/v1/messages")
            .expect("authorize Anthropic endpoint");
    let adapter = AnthropicAdapter::new(
        &AnthropicConfig::default(),
        ApiKey::new(credential("ANTHROPIC_API_KEY")).expect("valid Anthropic key"),
        &authorization,
    )
    .expect("Anthropic adapter");
    assert_tool_round_trip(&adapter, model("REVOOT_LIVE_ANTHROPIC_MODEL")).await;
}

#[tokio::test]
#[ignore = "requires OPENAI_API_KEY and REVOOT_LIVE_OPENAI_MODEL"]
async fn openai_live_contract() {
    let authorization =
        authorize_standard_provider("openai", "https://api.openai.com/v1/responses")
            .expect("authorize OpenAI endpoint");
    let adapter = OpenAiAdapter::new(
        &OpenAiConfig::default(),
        ApiKey::new(credential("OPENAI_API_KEY")).expect("valid OpenAI key"),
        &authorization,
    )
    .expect("OpenAI adapter");
    assert_tool_round_trip(&adapter, model("REVOOT_LIVE_OPENAI_MODEL")).await;
}
