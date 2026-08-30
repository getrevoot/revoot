//! Direct Anthropic Messages API adapter.

use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use revoot_core::provider::{
    CancellationToken, ModelContent, ModelFinishReason, ModelRequest, ModelResponse, ModelRole,
    ModelStreamEvent, ModelUsage, ProviderAdapter, ProviderError, ProviderErrorKind,
    ProviderFuture,
};
use serde_json::{Map, Value, json};

use super::{
    ApiKey, DirectHttp, ProviderBuildError, ProviderHttpLimits, credential_header, json_error,
};

pub const ADAPTER_ID: &str = "anthropic";
pub const DEFAULT_API_VERSION: &str = "2023-06-01";
const MAX_SSE_EVENT_BYTES: usize = 1024 * 1024;
const MAX_SSE_EVENTS: usize = 4_096;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnthropicConfig {
    pub api_version: String,
    pub limits: ProviderHttpLimits,
}

impl Default for AnthropicConfig {
    fn default() -> Self {
        Self {
            api_version: DEFAULT_API_VERSION.to_owned(),
            limits: ProviderHttpLimits::default(),
        }
    }
}

pub struct AnthropicAdapter {
    http: DirectHttp,
    api_key: ApiKey,
    api_version: HeaderValue,
}

impl AnthropicAdapter {
    /// Build a direct, DNS-pinned Anthropic Messages adapter.
    ///
    /// The authorized endpoint is expected to be exactly the endpoint selected
    /// by the caller's provider-egress policy (normally `/v1/messages`).
    ///
    /// # Errors
    ///
    /// Returns an error for invalid credentials, headers, limits, or egress
    /// authorization.
    pub fn new(
        config: &AnthropicConfig,
        api_key: ApiKey,
        authorization: &revoot_core::AllowedProviderEgress,
    ) -> Result<Self, ProviderBuildError> {
        if config.api_version.is_empty()
            || config.api_version.len() > 64
            || !config
                .api_version
                .bytes()
                .all(|byte| byte.is_ascii_digit() || byte == b'-')
        {
            return Err(ProviderBuildError::InvalidEndpoint);
        }
        let mut api_version = HeaderValue::from_str(&config.api_version)
            .map_err(|_| ProviderBuildError::InvalidEndpoint)?;
        api_version.set_sensitive(false);
        Ok(Self {
            http: DirectHttp::build(ADAPTER_ID, authorization, config.limits)?,
            api_key,
            api_version,
        })
    }

    async fn execute(
        &self,
        request: &ModelRequest,
        cancellation: &CancellationToken,
    ) -> Result<ModelResponse, ProviderError> {
        request
            .validate()
            .map_err(|_| ProviderError::new(ProviderErrorKind::InvalidRequest, None, false))?;
        let body = serde_json::to_vec(&encode_request(request)).map_err(|_| json_error())?;
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("x-api-key"),
            credential_header(&self.api_key, b"")
                .map_err(|_| ProviderError::new(ProviderErrorKind::Authentication, None, false))?,
        );
        headers.insert(
            HeaderName::from_static("anthropic-version"),
            self.api_version.clone(),
        );
        let response = self.http.post_json(headers, body, cancellation).await?;
        debug_assert!(response.status.is_success());
        decode_response(&response.body)
    }
}

impl ProviderAdapter for AnthropicAdapter {
    fn adapter_id(&self) -> &'static str {
        ADAPTER_ID
    }

    fn complete<'a>(
        &'a self,
        request: &'a ModelRequest,
        cancellation: &'a CancellationToken,
    ) -> ProviderFuture<'a> {
        Box::pin(self.execute(request, cancellation))
    }
}

fn encode_request(request: &ModelRequest) -> Value {
    let messages: Vec<_> = request
        .messages
        .iter()
        .map(|message| {
            let role = match message.role {
                ModelRole::User => "user",
                ModelRole::Assistant => "assistant",
            };
            let content: Vec<_> = message.content.iter().map(encode_content).collect();
            json!({"role": role, "content": content})
        })
        .collect();
    let tools: Vec<_> = request
        .tools
        .iter()
        .map(|tool| {
            json!({
                "name": tool.name,
                "description": tool.description,
                "input_schema": tool.input_schema,
            })
        })
        .collect();
    let mut body = Map::from_iter([
        ("model".to_owned(), json!(request.model)),
        ("messages".to_owned(), Value::Array(messages)),
        ("tools".to_owned(), Value::Array(tools)),
        ("max_tokens".to_owned(), json!(request.max_output_tokens)),
        ("stream".to_owned(), Value::Bool(false)),
    ]);
    if let Some(system) = &request.system {
        body.insert("system".to_owned(), json!(system));
    }
    if let Some(temperature) = request.temperature {
        body.insert("temperature".to_owned(), json!(temperature));
    }
    Value::Object(body)
}

fn encode_content(content: &ModelContent) -> Value {
    match content {
        ModelContent::Text { text } => json!({"type": "text", "text": text}),
        ModelContent::ToolUse { id, name, input } => {
            json!({"type": "tool_use", "id": id, "name": name, "input": input})
        }
        ModelContent::ToolResult {
            tool_use_id,
            content,
            is_error,
        } => json!({
            "type": "tool_result",
            "tool_use_id": tool_use_id,
            "content": content,
            "is_error": is_error,
        }),
    }
}

fn decode_response(body: &[u8]) -> Result<ModelResponse, ProviderError> {
    let value: Value = serde_json::from_slice(body).map_err(|_| json_error())?;
    let root = object(&value)?;
    if string(root, "type")? != "message" || string(root, "role")? != "assistant" {
        return Err(json_error());
    }
    let id = bounded_string(root, "id", 256)?;
    let model = bounded_string(root, "model", 256)?;
    let blocks = array(root, "content")?;
    if blocks.len() > revoot_core::MAX_CONTENT_BLOCKS {
        return Err(json_error());
    }
    let content = blocks
        .iter()
        .map(decode_content)
        .collect::<Result<Vec<_>, _>>()?;
    let finish_reason = match string(root, "stop_reason")? {
        "end_turn" | "stop_sequence" => ModelFinishReason::Stop,
        "tool_use" => ModelFinishReason::ToolUse,
        "max_tokens" => ModelFinishReason::Length,
        "refusal" => ModelFinishReason::ContentFilter,
        _ => ModelFinishReason::Unknown,
    };
    let usage = decode_usage(required(root, "usage")?)?;
    Ok(ModelResponse {
        provider_response_id: Some(id),
        model,
        content,
        finish_reason,
        usage,
    })
}

fn decode_content(value: &Value) -> Result<ModelContent, ProviderError> {
    let content = object(value)?;
    match string(content, "type")? {
        "text" => Ok(ModelContent::Text {
            text: bounded_string(content, "text", revoot_core::MAX_TEXT_BYTES)?,
        }),
        "tool_use" => {
            let input = required(content, "input")?.clone();
            if serde_json::to_vec(&input)
                .map_or(true, |bytes| bytes.len() > revoot_core::MAX_TOOL_JSON_BYTES)
            {
                return Err(json_error());
            }
            Ok(ModelContent::ToolUse {
                id: bounded_string(content, "id", revoot_core::MAX_TOOL_ID_BYTES)?,
                name: bounded_string(content, "name", revoot_core::MAX_TOOL_NAME_BYTES)?,
                input,
            })
        }
        _ => Err(json_error()),
    }
}

fn decode_usage(value: &Value) -> Result<ModelUsage, ProviderError> {
    let usage = object(value)?;
    let cached = optional_u64(usage, "cache_read_input_tokens")?.unwrap_or(0);
    let created = optional_u64(usage, "cache_creation_input_tokens")?.unwrap_or(0);
    Ok(ModelUsage {
        input_tokens: u64_field(usage, "input_tokens")?,
        output_tokens: u64_field(usage, "output_tokens")?,
        cached_input_tokens: cached.saturating_add(created),
    })
}

/// Decode a recorded Anthropic SSE stream into provider-neutral events.
///
/// This parser is also used by conformance fixtures before streaming transport
/// is enabled in the agent loop.
///
/// # Errors
///
/// Rejects malformed, unknown, oversized, or incomplete event data.
pub fn decode_sse_fixture(input: &[u8]) -> Result<Vec<ModelStreamEvent>, ProviderError> {
    if input.len() > 4 * 1024 * 1024 {
        return Err(json_error());
    }
    let text = std::str::from_utf8(input).map_err(|_| json_error())?;
    let mut events = Vec::new();
    let mut input_usage = ModelUsage::default();
    for record in text
        .split("\n\n")
        .filter(|record| !record.trim().is_empty())
    {
        if record.len() > MAX_SSE_EVENT_BYTES || events.len() >= MAX_SSE_EVENTS {
            return Err(json_error());
        }
        let data = record
            .lines()
            .find_map(|line| line.strip_prefix("data: "))
            .ok_or_else(json_error)?;
        let value: Value = serde_json::from_str(data).map_err(|_| json_error())?;
        let root = object(&value)?;
        match string(root, "type")? {
            "message_start" => {
                let message = object(required(root, "message")?)?;
                input_usage = decode_usage(required(message, "usage")?)?;
                events.push(ModelStreamEvent::MessageStart {
                    provider_response_id: Some(bounded_string(message, "id", 256)?),
                    model: bounded_string(message, "model", 256)?,
                });
            }
            "content_block_start" => {
                let index = u32_field(root, "index")?;
                let block = object(required(root, "content_block")?)?;
                if string(block, "type")? == "tool_use" {
                    events.push(ModelStreamEvent::ToolUseStart {
                        index,
                        id: bounded_string(block, "id", revoot_core::MAX_TOOL_ID_BYTES)?,
                        name: bounded_string(block, "name", revoot_core::MAX_TOOL_NAME_BYTES)?,
                    });
                }
            }
            "content_block_delta" => {
                let index = u32_field(root, "index")?;
                let delta = object(required(root, "delta")?)?;
                match string(delta, "type")? {
                    "text_delta" => events.push(ModelStreamEvent::TextDelta {
                        text: bounded_string(delta, "text", revoot_core::MAX_TEXT_BYTES)?,
                    }),
                    "input_json_delta" => events.push(ModelStreamEvent::ToolInputDelta {
                        index,
                        partial_json: bounded_string(
                            delta,
                            "partial_json",
                            revoot_core::MAX_TOOL_JSON_BYTES,
                        )?,
                    }),
                    _ => return Err(json_error()),
                }
            }
            "message_delta" => {
                let delta = object(required(root, "delta")?)?;
                let usage = object(required(root, "usage")?)?;
                input_usage.output_tokens = u64_field(usage, "output_tokens")?;
                let finish_reason = match string(delta, "stop_reason")? {
                    "end_turn" | "stop_sequence" => ModelFinishReason::Stop,
                    "tool_use" => ModelFinishReason::ToolUse,
                    "max_tokens" => ModelFinishReason::Length,
                    "refusal" => ModelFinishReason::ContentFilter,
                    _ => ModelFinishReason::Unknown,
                };
                events.push(ModelStreamEvent::MessageComplete {
                    finish_reason,
                    usage: input_usage,
                });
            }
            "ping" | "content_block_stop" | "message_stop" => {}
            "error" => {
                return Err(ProviderError::new(
                    ProviderErrorKind::Unavailable,
                    None,
                    true,
                ));
            }
            _ => return Err(json_error()),
        }
    }
    if events.is_empty() {
        return Err(json_error());
    }
    Ok(events)
}

fn object(value: &Value) -> Result<&Map<String, Value>, ProviderError> {
    value.as_object().ok_or_else(json_error)
}

fn required<'a>(object: &'a Map<String, Value>, key: &str) -> Result<&'a Value, ProviderError> {
    object.get(key).ok_or_else(json_error)
}

fn string<'a>(object: &'a Map<String, Value>, key: &str) -> Result<&'a str, ProviderError> {
    required(object, key)?.as_str().ok_or_else(json_error)
}

fn bounded_string(
    object: &Map<String, Value>,
    key: &str,
    max: usize,
) -> Result<String, ProviderError> {
    let value = string(object, key)?;
    if value.len() > max || value.contains('\0') {
        return Err(json_error());
    }
    Ok(value.to_owned())
}

fn array<'a>(object: &'a Map<String, Value>, key: &str) -> Result<&'a [Value], ProviderError> {
    required(object, key)?
        .as_array()
        .map(Vec::as_slice)
        .ok_or_else(json_error)
}

fn u64_field(object: &Map<String, Value>, key: &str) -> Result<u64, ProviderError> {
    required(object, key)?.as_u64().ok_or_else(json_error)
}

fn u32_field(object: &Map<String, Value>, key: &str) -> Result<u32, ProviderError> {
    u32::try_from(u64_field(object, key)?).map_err(|_| json_error())
}

fn optional_u64(object: &Map<String, Value>, key: &str) -> Result<Option<u64>, ProviderError> {
    object
        .get(key)
        .map(|value| value.as_u64().ok_or_else(json_error))
        .transpose()
}

#[cfg(test)]
mod tests {
    use super::*;
    use revoot_core::{ModelMessage, ModelTool};

    #[test]
    fn request_fixture_matches_messages_api_shape() {
        let request = ModelRequest {
            model: "claude-test".to_owned(),
            system: Some("Review code".to_owned()),
            messages: vec![ModelMessage {
                role: ModelRole::User,
                content: vec![ModelContent::Text {
                    text: "Inspect".to_owned(),
                }],
            }],
            tools: vec![ModelTool {
                name: "read_file".to_owned(),
                description: "Read file".to_owned(),
                input_schema: json!({"type":"object"}),
            }],
            max_output_tokens: 512,
            temperature: Some(0.0),
        };
        let encoded = encode_request(&request);
        assert_eq!(encoded["stream"], false);
        assert_eq!(encoded["tools"][0]["input_schema"]["type"], "object");
        assert!(encoded.get("api_key").is_none());
    }

    #[test]
    fn recorded_response_fixture_normalizes_tool_use() {
        let fixture = br#"{
          "id":"msg_01","type":"message","role":"assistant","model":"claude-test",
          "content":[{"type":"text","text":"Checking."},{"type":"tool_use","id":"toolu_01","name":"read_file","input":{"path":"src/lib.rs"}}],
          "stop_reason":"tool_use","stop_sequence":null,
          "usage":{"input_tokens":21,"output_tokens":8,"cache_read_input_tokens":5}
        }"#;
        let response = decode_response(fixture).expect("valid recorded fixture");
        assert_eq!(response.finish_reason, ModelFinishReason::ToolUse);
        assert_eq!(response.usage.cached_input_tokens, 5);
        assert!(matches!(response.content[1], ModelContent::ToolUse { .. }));
    }

    #[test]
    fn recorded_sse_fixture_normalizes_events() {
        let fixture = br#"event: message_start
data: {"type":"message_start","message":{"id":"msg_01","type":"message","role":"assistant","model":"claude-test","content":[],"stop_reason":null,"stop_sequence":null,"usage":{"input_tokens":12,"output_tokens":0}}}

event: content_block_delta
data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Looks good"}}

event: message_delta
data: {"type":"message_delta","delta":{"stop_reason":"end_turn","stop_sequence":null},"usage":{"output_tokens":3}}

event: message_stop
data: {"type":"message_stop"}

"#;
        let events = decode_sse_fixture(fixture).expect("valid recorded stream");
        assert_eq!(events.len(), 3);
        assert!(matches!(events[1], ModelStreamEvent::TextDelta { .. }));
        assert!(matches!(
            events[2],
            ModelStreamEvent::MessageComplete {
                usage: ModelUsage {
                    input_tokens: 12,
                    output_tokens: 3,
                    ..
                },
                ..
            }
        ));
    }

    #[test]
    fn malformed_fixture_does_not_leak_body_in_error() {
        let fixture = br#"{"type":"message","unexpected":"SENSITIVE_PAYLOAD_MARKER"}"#;
        let error = decode_response(fixture).expect_err("incomplete fixture");
        assert!(!format!("{error:?}").contains("SENSITIVE_PAYLOAD_MARKER"));
    }
}
