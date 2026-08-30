//! Direct `OpenAI` Responses API adapter.

use reqwest::header::{AUTHORIZATION, HeaderMap};
use revoot_core::provider::{
    CancellationToken, ModelContent, ModelFinishReason, ModelRequest, ModelResponse, ModelRole,
    ModelStreamEvent, ModelUsage, ProviderAdapter, ProviderError, ProviderErrorKind,
    ProviderFuture,
};
use serde_json::{Map, Value, json};

use super::{
    ApiKey, DirectHttp, ProviderBuildError, ProviderHttpLimits, credential_header, json_error,
};

pub const ADAPTER_ID: &str = "openai";
const MAX_SSE_EVENT_BYTES: usize = 1024 * 1024;
const MAX_SSE_EVENTS: usize = 4_096;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct OpenAiConfig {
    pub limits: ProviderHttpLimits,
}

pub struct OpenAiAdapter {
    http: DirectHttp,
    api_key: ApiKey,
}

impl OpenAiAdapter {
    /// Build a direct, DNS-pinned `OpenAI` Responses adapter.
    ///
    /// The egress authorization selects the exact Responses endpoint without
    /// accepting redirects or ambient proxy configuration.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid limits or egress authorization.
    pub fn new(
        config: &OpenAiConfig,
        api_key: ApiKey,
        authorization: &revoot_core::AllowedProviderEgress,
    ) -> Result<Self, ProviderBuildError> {
        Ok(Self {
            http: DirectHttp::build(ADAPTER_ID, authorization, config.limits)?,
            api_key,
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
            AUTHORIZATION,
            credential_header(&self.api_key, b"Bearer ")
                .map_err(|_| ProviderError::new(ProviderErrorKind::Authentication, None, false))?,
        );
        let response = self.http.post_json(headers, body, cancellation).await?;
        debug_assert!(response.status.is_success());
        decode_response(&response.body)
    }
}

impl ProviderAdapter for OpenAiAdapter {
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
    let mut input = Vec::new();
    for message in &request.messages {
        encode_message(message.role, &message.content, &mut input);
    }
    let tools: Vec<_> = request
        .tools
        .iter()
        .map(|tool| {
            json!({
                "type": "function",
                "name": tool.name,
                "description": tool.description,
                "parameters": tool.input_schema
            })
        })
        .collect();
    let mut body = Map::from_iter([
        ("model".to_owned(), json!(request.model)),
        ("input".to_owned(), Value::Array(input)),
        ("tools".to_owned(), Value::Array(tools)),
        (
            "max_output_tokens".to_owned(),
            json!(request.max_output_tokens),
        ),
        ("store".to_owned(), Value::Bool(false)),
    ]);
    if let Some(system) = &request.system {
        body.insert("instructions".to_owned(), json!(system));
    }
    if let Some(temperature) = request.temperature {
        body.insert("temperature".to_owned(), json!(temperature));
    }
    Value::Object(body)
}

fn encode_message(role: ModelRole, content: &[ModelContent], output: &mut Vec<Value>) {
    let text_blocks = content
        .iter()
        .filter_map(|content| match content {
            ModelContent::Text { text } => Some(json!({
                "type": if matches!(role, ModelRole::User) {
                    "input_text"
                } else {
                    "output_text"
                },
                "text": text
            })),
            _ => None,
        })
        .collect::<Vec<_>>();
    let role_name = match role {
        ModelRole::User => "user",
        ModelRole::Assistant => "assistant",
    };
    if !text_blocks.is_empty() {
        output.push(json!({
            "type": "message",
            "role": role_name,
            "content": text_blocks
        }));
    }
    for block in content {
        match block {
            ModelContent::ToolUse { id, name, input } => output.push(json!({
                "type": "function_call",
                "call_id": id,
                "name": name,
                "arguments": input.to_string()
            })),
            ModelContent::ToolResult {
                tool_use_id,
                content,
                is_error,
            } => output.push(json!({
                "type": "function_call_output",
                "call_id": tool_use_id,
                "output": if *is_error { format!("ERROR: {content}") } else { content.clone() }
            })),
            ModelContent::Text { .. } => {}
        }
    }
}

fn decode_response(body: &[u8]) -> Result<ModelResponse, ProviderError> {
    let value: Value = serde_json::from_slice(body).map_err(|_| json_error())?;
    let root = object(&value)?;
    if string(root, "object")? != "response"
        || !matches!(string(root, "status")?, "completed" | "incomplete")
    {
        return Err(json_error());
    }
    let mut content = Vec::new();
    let mut used_tool = false;
    for item in array(root, "output")? {
        if content.len() >= revoot_core::MAX_CONTENT_BLOCKS {
            return Err(json_error());
        }
        let item = object(item)?;
        match string(item, "type")? {
            "message" => decode_message(item, &mut content)?,
            "function_call" => {
                content.push(decode_tool_call(item)?);
                used_tool = true;
            }
            // Reasoning items are provider-owned opaque state. They are not
            // exposed to the review agent or retained.
            "reasoning" => {}
            _ => return Err(json_error()),
        }
    }
    let usage = decode_usage(required(root, "usage")?)?;
    let finish_reason = if used_tool {
        ModelFinishReason::ToolUse
    } else if string(root, "status")? == "incomplete" {
        decode_incomplete_reason(root)
    } else {
        ModelFinishReason::Stop
    };
    Ok(ModelResponse {
        provider_response_id: Some(bounded_string(root, "id", 256)?),
        model: bounded_string(root, "model", 256)?,
        content,
        finish_reason,
        usage,
    })
}

fn decode_message(
    message: &Map<String, Value>,
    output: &mut Vec<ModelContent>,
) -> Result<(), ProviderError> {
    if string(message, "role")? != "assistant" {
        return Err(json_error());
    }
    for block in array(message, "content")? {
        let block = object(block)?;
        if string(block, "type")? != "output_text" {
            return Err(json_error());
        }
        let text = bounded_string(block, "text", revoot_core::MAX_TEXT_BYTES)?;
        if !text.is_empty() {
            if output.len() >= revoot_core::MAX_CONTENT_BLOCKS {
                return Err(json_error());
            }
            output.push(ModelContent::Text { text });
        }
    }
    Ok(())
}

fn decode_tool_call(call: &Map<String, Value>) -> Result<ModelContent, ProviderError> {
    if string(call, "type")? != "function_call" {
        return Err(json_error());
    }
    let arguments = string(call, "arguments")?;
    if arguments.len() > revoot_core::MAX_TOOL_JSON_BYTES {
        return Err(json_error());
    }
    let input = serde_json::from_str(arguments).map_err(|_| json_error())?;
    Ok(ModelContent::ToolUse {
        id: bounded_string(call, "call_id", revoot_core::MAX_TOOL_ID_BYTES)?,
        name: bounded_string(call, "name", revoot_core::MAX_TOOL_NAME_BYTES)?,
        input,
    })
}

fn decode_usage(value: &Value) -> Result<ModelUsage, ProviderError> {
    let usage = object(value)?;
    let cached_input_tokens = usage
        .get("input_tokens_details")
        .and_then(Value::as_object)
        .and_then(|details| details.get("cached_tokens"))
        .and_then(Value::as_u64)
        .unwrap_or(0);
    Ok(ModelUsage {
        input_tokens: u64_field(usage, "input_tokens")?,
        output_tokens: u64_field(usage, "output_tokens")?,
        cached_input_tokens,
    })
}

fn decode_incomplete_reason(root: &Map<String, Value>) -> ModelFinishReason {
    match root
        .get("incomplete_details")
        .and_then(Value::as_object)
        .and_then(|details| details.get("reason"))
        .and_then(Value::as_str)
    {
        Some("max_output_tokens") => ModelFinishReason::Length,
        Some("content_filter") => ModelFinishReason::ContentFilter,
        _ => ModelFinishReason::Unknown,
    }
}

/// Decode a recorded `OpenAI` Responses SSE stream into the provider-neutral contract.
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
    let mut started = false;
    let mut completed = false;
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
            "response.created" => {
                if started {
                    return Err(json_error());
                }
                let response = object(required(root, "response")?)?;
                events.push(ModelStreamEvent::MessageStart {
                    provider_response_id: Some(bounded_string(response, "id", 256)?),
                    model: bounded_string(response, "model", 256)?,
                });
                started = true;
            }
            "response.output_text.delta" => {
                let text = bounded_string(root, "delta", revoot_core::MAX_TEXT_BYTES)?;
                events.push(ModelStreamEvent::TextDelta { text });
            }
            "response.output_item.added" => {
                let item = object(required(root, "item")?)?;
                if string(item, "type")? == "function_call" {
                    events.push(ModelStreamEvent::ToolUseStart {
                        index: u32_field(root, "output_index")?,
                        id: bounded_string(item, "call_id", revoot_core::MAX_TOOL_ID_BYTES)?,
                        name: bounded_string(item, "name", revoot_core::MAX_TOOL_NAME_BYTES)?,
                    });
                }
            }
            "response.function_call_arguments.delta" => {
                events.push(ModelStreamEvent::ToolInputDelta {
                    index: u32_field(root, "output_index")?,
                    partial_json: bounded_string(root, "delta", revoot_core::MAX_TOOL_JSON_BYTES)?,
                });
            }
            "response.completed" | "response.incomplete" => {
                let response = object(required(root, "response")?)?;
                let used_tool = array(response, "output")?.iter().any(|item| {
                    item.as_object()
                        .and_then(|item| item.get("type"))
                        .and_then(Value::as_str)
                        == Some("function_call")
                });
                let finish_reason = if used_tool {
                    ModelFinishReason::ToolUse
                } else if string(response, "status")? == "incomplete" {
                    decode_incomplete_reason(response)
                } else {
                    ModelFinishReason::Stop
                };
                events.push(ModelStreamEvent::MessageComplete {
                    finish_reason,
                    usage: decode_usage(required(response, "usage")?)?,
                });
                completed = true;
            }
            "response.in_progress"
            | "response.output_item.done"
            | "response.content_part.added"
            | "response.content_part.done"
            | "response.output_text.done"
            | "response.function_call_arguments.done" => {}
            _ => return Err(json_error()),
        }
    }
    if !started || !completed {
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

#[cfg(test)]
mod tests {
    use super::*;
    use revoot_core::provider::{ModelMessage, ModelTool};

    #[test]
    fn request_fixture_maps_tool_results_without_credentials() {
        let request = ModelRequest {
            model: "openai-test".to_owned(),
            system: Some("Review code".to_owned()),
            messages: vec![
                ModelMessage {
                    role: ModelRole::Assistant,
                    content: vec![ModelContent::ToolUse {
                        id: "call_01".to_owned(),
                        name: "read_file".to_owned(),
                        input: json!({"path":"src/lib.rs"}),
                    }],
                },
                ModelMessage {
                    role: ModelRole::User,
                    content: vec![ModelContent::ToolResult {
                        tool_use_id: "call_01".to_owned(),
                        content: "source".to_owned(),
                        is_error: false,
                    }],
                },
            ],
            tools: vec![ModelTool {
                name: "read_file".to_owned(),
                description: "Read file".to_owned(),
                input_schema: json!({"type":"object","additionalProperties":false}),
            }],
            max_output_tokens: 512,
            temperature: None,
        };
        let encoded = encode_request(&request);
        assert_eq!(encoded["input"][0]["type"], "function_call");
        assert_eq!(encoded["input"][1]["type"], "function_call_output");
        assert_eq!(encoded["tools"][0]["name"], "read_file");
        assert_eq!(encoded["store"], false);
        assert!(encoded.get("authorization").is_none());
    }

    #[test]
    fn recorded_response_fixture_normalizes_tool_call() {
        let fixture = br#"{
          "id":"resp-01","object":"response","status":"completed","model":"openai-test",
          "output":[
            {"id":"reason-1","type":"reasoning","summary":[]},
            {"id":"fc-1","type":"function_call","call_id":"call_01","name":"read_file","arguments":"{\"path\":\"src/lib.rs\"}","status":"completed"}
          ],
          "usage":{"input_tokens":20,"output_tokens":7,"total_tokens":27,"input_tokens_details":{"cached_tokens":4}}
        }"#;
        let response = decode_response(fixture).expect("valid recorded fixture");
        assert_eq!(response.finish_reason, ModelFinishReason::ToolUse);
        assert_eq!(response.usage.cached_input_tokens, 4);
        assert!(matches!(response.content[0], ModelContent::ToolUse { .. }));
    }

    #[test]
    fn recorded_sse_fixture_normalizes_deltas() {
        let fixture = br#"data: {"type":"response.created","sequence_number":0,"response":{"id":"resp-01","object":"response","status":"in_progress","model":"openai-test","output":[]}}

data: {"type":"response.output_text.delta","sequence_number":1,"output_index":0,"content_index":0,"delta":"Review complete"}

data: {"type":"response.completed","sequence_number":2,"response":{"id":"resp-01","object":"response","status":"completed","model":"openai-test","output":[{"id":"msg-1","type":"message","role":"assistant","content":[{"type":"output_text","text":"Review complete","annotations":[]}]}],"usage":{"input_tokens":10,"output_tokens":2,"total_tokens":12,"input_tokens_details":{"cached_tokens":1}}}}

"#;
        let events = decode_sse_fixture(fixture).expect("valid recorded stream");
        assert!(matches!(events[0], ModelStreamEvent::MessageStart { .. }));
        assert!(matches!(events[1], ModelStreamEvent::TextDelta { .. }));
        assert!(matches!(
            events.last(),
            Some(ModelStreamEvent::MessageComplete {
                usage: ModelUsage {
                    input_tokens: 10,
                    output_tokens: 2,
                    ..
                },
                ..
            })
        ));
    }

    #[test]
    fn invalid_arguments_are_a_protocol_error_without_payload() {
        let fixture = br#"{
          "id":"resp-01","object":"response","status":"completed","model":"openai-test",
          "output":[{"id":"fc-1","type":"function_call","call_id":"call_01","name":"read_file","arguments":"SENSITIVE_PAYLOAD_MARKER","status":"completed"}],
          "usage":{"input_tokens":1,"output_tokens":1}
        }"#;
        let error = decode_response(fixture).expect_err("arguments are not JSON");
        assert_eq!(error.kind(), ProviderErrorKind::Protocol);
        assert!(!format!("{error:?}").contains("SENSITIVE_PAYLOAD_MARKER"));
    }

    #[test]
    fn nested_message_content_cannot_exceed_the_global_block_bound() {
        let blocks: Vec<_> = (0..=revoot_core::MAX_CONTENT_BLOCKS)
            .map(|index| json!({"type":"output_text", "text":format!("line-{index}")}))
            .collect();
        let fixture = json!({
            "id":"resp-01",
            "object":"response",
            "status":"completed",
            "model":"openai-test",
            "output":[{"id":"msg-1", "type":"message", "role":"assistant", "content":blocks}],
            "usage":{"input_tokens":1, "output_tokens":1}
        });
        let bytes = serde_json::to_vec(&fixture).expect("fixture serialization");
        let error = decode_response(&bytes).expect_err("content bound");
        assert_eq!(error.kind(), ProviderErrorKind::Protocol);
    }
}
