//! Provider-neutral contracts for direct model adapters.
//!
//! The review agent speaks only these types. Provider wire formats, HTTP
//! headers, credentials, and error bodies stay in the trusted adapter layer.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const MAX_MODEL_MESSAGES: usize = 512;
pub const MAX_MODEL_TOOLS: usize = 64;
pub const MAX_CONTENT_BLOCKS: usize = 1_024;
pub const MAX_TEXT_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_TOOL_JSON_BYTES: usize = 1024 * 1024;
pub const MAX_TOOL_NAME_BYTES: usize = 128;
pub const MAX_TOOL_ID_BYTES: usize = 256;
pub const MAX_MODEL_ID_BYTES: usize = 256;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelRole {
    User,
    Assistant,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ModelContent {
    Text {
        text: String,
    },
    ToolUse {
        id: String,
        name: String,
        input: Value,
    },
    ToolResult {
        tool_use_id: String,
        content: String,
        is_error: bool,
    },
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModelMessage {
    pub role: ModelRole,
    pub content: Vec<ModelContent>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModelTool {
    pub name: String,
    pub description: String,
    /// A JSON Schema object. Adapters must send it without broadening it.
    pub input_schema: Value,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModelRequest {
    pub model: String,
    pub system: Option<String>,
    pub messages: Vec<ModelMessage>,
    pub tools: Vec<ModelTool>,
    pub max_output_tokens: u32,
    pub temperature: Option<f32>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ModelRequestError {
    Model,
    Messages,
    Content,
    Text,
    ToolCount,
    ToolName,
    ToolId,
    ToolSchema,
    OutputTokens,
    Temperature,
}

impl ModelRequest {
    /// Validate size and shape before any credential is attached to a request.
    ///
    /// # Errors
    ///
    /// Returns the first invalid or over-limit request field.
    pub fn validate(&self) -> Result<(), ModelRequestError> {
        if !bounded_label(&self.model, MAX_MODEL_ID_BYTES) {
            return Err(ModelRequestError::Model);
        }
        if self.messages.is_empty() || self.messages.len() > MAX_MODEL_MESSAGES {
            return Err(ModelRequestError::Messages);
        }
        if self.tools.len() > MAX_MODEL_TOOLS {
            return Err(ModelRequestError::ToolCount);
        }
        if self.max_output_tokens == 0 {
            return Err(ModelRequestError::OutputTokens);
        }
        if self
            .temperature
            .is_some_and(|value| !value.is_finite() || !(0.0..=2.0).contains(&value))
        {
            return Err(ModelRequestError::Temperature);
        }
        if self.system.as_ref().is_some_and(|text| !bounded_text(text)) {
            return Err(ModelRequestError::Text);
        }
        for tool in &self.tools {
            if !bounded_label(&tool.name, MAX_TOOL_NAME_BYTES) {
                return Err(ModelRequestError::ToolName);
            }
            if !bounded_text(&tool.description)
                || !tool.input_schema.is_object()
                || json_size(&tool.input_schema) > MAX_TOOL_JSON_BYTES
            {
                return Err(ModelRequestError::ToolSchema);
            }
        }
        let mut blocks = 0_usize;
        for message in &self.messages {
            if message.content.is_empty() {
                return Err(ModelRequestError::Content);
            }
            blocks = blocks
                .checked_add(message.content.len())
                .ok_or(ModelRequestError::Content)?;
            if blocks > MAX_CONTENT_BLOCKS {
                return Err(ModelRequestError::Content);
            }
            for content in &message.content {
                validate_content(content)?;
            }
        }
        Ok(())
    }
}

fn validate_content(content: &ModelContent) -> Result<(), ModelRequestError> {
    match content {
        ModelContent::Text { text } => {
            if !bounded_text(text) {
                return Err(ModelRequestError::Text);
            }
        }
        ModelContent::ToolUse { id, name, input } => {
            if !bounded_label(id, MAX_TOOL_ID_BYTES) {
                return Err(ModelRequestError::ToolId);
            }
            if !bounded_label(name, MAX_TOOL_NAME_BYTES) {
                return Err(ModelRequestError::ToolName);
            }
            if json_size(input) > MAX_TOOL_JSON_BYTES {
                return Err(ModelRequestError::ToolSchema);
            }
        }
        ModelContent::ToolResult {
            tool_use_id,
            content,
            ..
        } => {
            if !bounded_label(tool_use_id, MAX_TOOL_ID_BYTES) {
                return Err(ModelRequestError::ToolId);
            }
            if !bounded_text(content) {
                return Err(ModelRequestError::Text);
            }
        }
    }
    Ok(())
}

fn bounded_text(value: &str) -> bool {
    value.len() <= MAX_TEXT_BYTES && !value.contains('\0')
}

fn bounded_label(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value
            .bytes()
            .all(|byte| !byte.is_ascii_control() && !byte.is_ascii_whitespace())
}

fn json_size(value: &Value) -> usize {
    serde_json::to_vec(value).map_or(usize::MAX, |encoded| encoded.len())
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModelUsage {
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cached_input_tokens: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelFinishReason {
    Stop,
    ToolUse,
    Length,
    ContentFilter,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModelResponse {
    pub provider_response_id: Option<String>,
    pub model: String,
    pub content: Vec<ModelContent>,
    pub finish_reason: ModelFinishReason,
    pub usage: ModelUsage,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ModelStreamEvent {
    MessageStart {
        provider_response_id: Option<String>,
        model: String,
    },
    TextDelta {
        text: String,
    },
    ToolUseStart {
        index: u32,
        id: String,
        name: String,
    },
    ToolInputDelta {
        index: u32,
        partial_json: String,
    },
    MessageComplete {
        finish_reason: ModelFinishReason,
        usage: ModelUsage,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ProviderCancellationReason {
    UserRequested = 1,
    Deadline = 2,
    Shutdown = 3,
}

/// Cloneable, provider-neutral cooperative cancellation signal.
#[derive(Clone, Default)]
pub struct CancellationToken {
    reason: Arc<AtomicU8>,
}

impl CancellationToken {
    pub fn cancel(&self, reason: ProviderCancellationReason) {
        let _ = self
            .reason
            .compare_exchange(0, reason as u8, Ordering::AcqRel, Ordering::Acquire);
    }

    #[must_use]
    pub fn reason(&self) -> Option<ProviderCancellationReason> {
        match self.reason.load(Ordering::Acquire) {
            1 => Some(ProviderCancellationReason::UserRequested),
            2 => Some(ProviderCancellationReason::Deadline),
            3 => Some(ProviderCancellationReason::Shutdown),
            _ => None,
        }
    }

    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.reason().is_some()
    }
}

impl std::fmt::Debug for CancellationToken {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CancellationToken")
            .field("reason", &self.reason())
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderErrorKind {
    InvalidRequest,
    Authentication,
    PermissionDenied,
    RateLimited,
    Timeout,
    Cancelled,
    Unavailable,
    Protocol,
    ResponseTooLarge,
}

/// A deliberately payload-free adapter error safe for logs and telemetry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProviderError {
    kind: ProviderErrorKind,
    status_code: Option<u16>,
    retryable: bool,
}

impl ProviderError {
    #[must_use]
    pub const fn new(kind: ProviderErrorKind, status_code: Option<u16>, retryable: bool) -> Self {
        Self {
            kind,
            status_code,
            retryable,
        }
    }

    #[must_use]
    pub const fn kind(self) -> ProviderErrorKind {
        self.kind
    }

    #[must_use]
    pub const fn status_code(self) -> Option<u16> {
        self.status_code
    }

    #[must_use]
    pub const fn retryable(self) -> bool {
        self.retryable
    }
}

impl std::fmt::Display for ProviderError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "provider request failed: {:?}", self.kind)
    }
}

impl std::error::Error for ProviderError {}

pub type ProviderFuture<'a> =
    Pin<Box<dyn Future<Output = Result<ModelResponse, ProviderError>> + Send + 'a>>;

/// Object-safe interface implemented by each direct provider adapter.
pub trait ProviderAdapter: Send + Sync {
    fn adapter_id(&self) -> &'static str;

    fn complete<'a>(
        &'a self,
        request: &'a ModelRequest,
        cancellation: &'a CancellationToken,
    ) -> ProviderFuture<'a>;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> ModelRequest {
        ModelRequest {
            model: "model-v1".to_owned(),
            system: Some("Review carefully.".to_owned()),
            messages: vec![ModelMessage {
                role: ModelRole::User,
                content: vec![ModelContent::Text {
                    text: "Inspect the diff.".to_owned(),
                }],
            }],
            tools: vec![ModelTool {
                name: "read_file".to_owned(),
                description: "Read a repository file".to_owned(),
                input_schema: serde_json::json!({"type": "object"}),
            }],
            max_output_tokens: 1024,
            temperature: Some(0.0),
        }
    }

    #[test]
    fn validates_bounded_request() {
        assert_eq!(request().validate(), Ok(()));
    }

    #[test]
    fn rejects_control_characters_in_request_labels() {
        let mut request = request();
        request.model = "bad\nmodel".to_owned();
        assert_eq!(request.validate(), Err(ModelRequestError::Model));
    }

    #[test]
    fn cancellation_preserves_first_reason() {
        let token = CancellationToken::default();
        token.cancel(ProviderCancellationReason::UserRequested);
        token.cancel(ProviderCancellationReason::Shutdown);
        assert_eq!(
            token.reason(),
            Some(ProviderCancellationReason::UserRequested)
        );
    }

    #[test]
    fn provider_error_has_no_payload_surface() {
        let error = ProviderError::new(ProviderErrorKind::Authentication, Some(401), false);
        assert_eq!(error.to_string(), "provider request failed: Authentication");
        assert_eq!(error.status_code(), Some(401));
    }
}
