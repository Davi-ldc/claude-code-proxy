use serde_json::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CodexFailureKind {
    RateLimit,
    /// The account's usage limit is exhausted until a reset hours away.
    /// Backing off cannot help; another account can serve the request.
    UsageLimit,
    Overloaded,
    Transient,
    Permanent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CodexStreamEventKind {
    Control,
    Structural,
    Semantic,
    TerminalSuccess,
    TerminalFailure,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CodexEventFailure {
    pub kind: CodexFailureKind,
    pub explicit_status: Option<u16>,
    pub status: u16,
    pub message: String,
    pub retry_after: Option<String>,
}

impl CodexEventFailure {
    pub fn retryable(&self) -> bool {
        !matches!(
            self.kind,
            CodexFailureKind::Permanent | CodexFailureKind::UsageLimit
        )
    }

    pub fn is_usage_limit(&self) -> bool {
        self.kind == CodexFailureKind::UsageLimit
    }

    pub fn client_status(&self) -> u16 {
        self.status
    }

    pub fn client_error_type(&self) -> &'static str {
        match self.client_status() {
            400 | 422 => "invalid_request_error",
            401 => "authentication_error",
            403 => "permission_error",
            413 => "request_too_large",
            429 => "rate_limit_error",
            529 => "overloaded_error",
            _ => "api_error",
        }
    }
}

pub(crate) fn classify_stream_event(payload: &Value) -> CodexStreamEventKind {
    if classify_event_failure(payload).is_some() {
        return CodexStreamEventKind::TerminalFailure;
    }
    match payload.get("type").and_then(Value::as_str) {
        Some("response.completed" | "response.done") => CodexStreamEventKind::TerminalSuccess,
        Some(
            "keepalive"
            | "response.created"
            | "response.in_progress"
            | "codex.rate_limits"
            | "response.web_search_call.in_progress"
            | "response.web_search_call.searching"
            | "response.web_search_call.completed",
        ) => CodexStreamEventKind::Control,
        Some(
            "response.reasoning_summary_text.delta"
            | "response.output_text.delta"
            | "response.function_call_arguments.delta",
        ) if payload
            .get("delta")
            .and_then(Value::as_str)
            .is_some_and(|delta| !delta.is_empty()) =>
        {
            CodexStreamEventKind::Semantic
        }
        Some("response.output_item.done")
            if matches!(
                payload.pointer("/item/type").and_then(Value::as_str),
                Some("function_call" | "web_search_call")
            ) =>
        {
            CodexStreamEventKind::Semantic
        }
        _ => CodexStreamEventKind::Structural,
    }
}

pub(crate) fn event_is_terminal(payload: &Value) -> bool {
    matches!(
        classify_stream_event(payload),
        CodexStreamEventKind::TerminalSuccess | CodexStreamEventKind::TerminalFailure
    )
}

pub(crate) fn event_is_success_terminal(payload: &Value) -> bool {
    classify_stream_event(payload) == CodexStreamEventKind::TerminalSuccess
}

pub(crate) fn event_error(payload: &Value) -> Option<&Value> {
    payload
        .get("error")
        .filter(|error| !error.is_null())
        .or_else(|| {
            payload
                .pointer("/response/error")
                .filter(|error| !error.is_null())
        })
}

/// Whether an upstream error object reports an exhausted account rather than
/// short-term throttling. Codex names the limit in `type`, or in `code` for
/// API quota, and states it in the message.
pub(crate) fn is_usage_limit_error(error: &Value) -> bool {
    let names_limit = |field: &str| {
        matches!(
            error.get(field).and_then(Value::as_str),
            Some("usage_limit_reached" | "insufficient_quota")
        )
    };
    names_limit("type")
        || names_limit("code")
        || error
            .get("message")
            .and_then(Value::as_str)
            .is_some_and(|message| message.to_ascii_lowercase().contains("usage limit"))
}

/// Seconds until an exhausted usage limit resets, from `resets_in_seconds` or
/// the absolute `resets_at` in Unix seconds.
pub(crate) fn usage_limit_retry_after(error: &Value) -> Option<String> {
    if let Some(seconds) = error.get("resets_in_seconds").and_then(Value::as_u64) {
        return Some(seconds.to_string());
    }
    let resets_at = error.get("resets_at").and_then(Value::as_u64)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs();
    Some(resets_at.saturating_sub(now).to_string())
}

pub(crate) fn response_is_incomplete_terminal(payload: &Value) -> bool {
    let event_type = payload.get("type").and_then(Value::as_str);
    let incomplete_details = payload.pointer("/response/incomplete_details");
    matches!(
        event_type,
        Some("response.completed" | "response.incomplete" | "response.done")
    ) && (event_type == Some("response.incomplete")
        || payload.pointer("/response/status").and_then(Value::as_str) == Some("incomplete")
        || incomplete_details.is_some_and(|details| !details.is_null()))
}

pub(crate) fn is_standard_max_output_tokens_incomplete(payload: &Value) -> bool {
    let status = payload.pointer("/response/status");
    payload.get("type").and_then(Value::as_str) == Some("response.incomplete")
        && (status.is_none() || status.and_then(Value::as_str) == Some("incomplete"))
        && payload
            .pointer("/response/incomplete_details/reason")
            .and_then(Value::as_str)
            == Some("max_output_tokens")
        && event_error(payload).is_none()
}

pub(crate) fn classify_event_failure(payload: &Value) -> Option<CodexEventFailure> {
    let event_type = payload.get("type").and_then(Value::as_str)?;
    let response_status = payload.pointer("/response/status").and_then(Value::as_str);
    if event_type == "codex.rate_limits" {
        return None;
    }
    if response_is_incomplete_terminal(payload) {
        let reason = payload
            .pointer("/response/incomplete_details/reason")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        return Some(CodexEventFailure {
            kind: CodexFailureKind::Transient,
            explicit_status: None,
            status: 503,
            message: format!("Incomplete response returned, reason: {reason}"),
            retry_after: None,
        });
    }
    let error = event_error(payload);
    if !matches!(event_type, "response.failed" | "response.error" | "error")
        && response_status != Some("failed")
        && error.is_none()
    {
        return None;
    }

    let explicit_status = numeric_status(payload)
        .or_else(|| {
            error
                .and_then(|value| value.get("status"))
                .and_then(Value::as_u64)
        })
        .and_then(|status| u16::try_from(status).ok());
    let code = error
        .and_then(|value| value.get("code"))
        .and_then(Value::as_str);
    let error_type = error
        .and_then(|value| value.get("type"))
        .and_then(Value::as_str);
    let raw_message = error
        .and_then(|value| value.get("message"))
        .and_then(Value::as_str);
    let message = match (code, raw_message) {
        (Some("cyber_policy"), None | Some("")) => {
            "This request has been flagged for possible cybersecurity risk.".to_string()
        }
        (Some("cyber_policy"), Some(message)) if message.trim().is_empty() => {
            "This request has been flagged for possible cybersecurity risk.".to_string()
        }
        (Some("invalid_prompt" | "bio_policy"), None) => "Invalid request.".to_string(),
        (_, Some(message)) => message.to_string(),
        _ => "Upstream error".to_string(),
    };
    let lower = message.to_ascii_lowercase();
    let context_window = code == Some("context_length_exceeded")
        || lower.contains("context window")
        || lower.contains("context length exceeded");
    let usage_limit = error.is_some_and(is_usage_limit_error);

    let kind = if usage_limit {
        CodexFailureKind::UsageLimit
    } else if context_window
        || matches!(
            code,
            Some(
                "context_length_exceeded"
                    | "usage_not_included"
                    | "cyber_policy"
                    | "invalid_prompt"
                    | "bio_policy"
            )
        )
    {
        CodexFailureKind::Permanent
    } else if matches!(code, Some("server_is_overloaded" | "slow_down")) {
        CodexFailureKind::Overloaded
    } else if explicit_status == Some(429) || lower.contains("rate limit") {
        CodexFailureKind::RateLimit
    } else if explicit_status == Some(529)
        || code == Some("overloaded_error")
        || error_type == Some("overloaded_error")
        || lower.contains("overloaded")
    {
        CodexFailureKind::Overloaded
    } else if explicit_status.is_some_and(|status| matches!(status, 500 | 502 | 503 | 504))
        || matches!(
            code,
            Some("server_error" | "internal_server_error" | "internal_error")
        )
        || matches!(
            error_type,
            Some("server_error" | "internal_server_error" | "internal_error")
        )
        || retryable_message(&lower)
    {
        CodexFailureKind::Transient
    } else if explicit_status.is_some() || matches!(event_type, "response.error" | "error") {
        CodexFailureKind::Permanent
    } else {
        // Native Codex treats an unclassified response.failed event as
        // retryable instead of silently converting it into a successful turn.
        CodexFailureKind::Transient
    };
    let status = if context_window {
        413
    } else {
        explicit_status.unwrap_or(match code {
            Some("cyber_policy" | "invalid_prompt" | "bio_policy") => 400,
            Some("insufficient_quota") => 429,
            Some("usage_not_included") => 403,
            _ => match kind {
                CodexFailureKind::RateLimit | CodexFailureKind::UsageLimit => 429,
                CodexFailureKind::Overloaded => 529,
                CodexFailureKind::Transient => 503,
                CodexFailureKind::Permanent => 500,
            },
        })
    };
    let retry_after = error
        .and_then(|value| value.get("retry_after"))
        .and_then(scalar_string_value)
        .or_else(|| {
            error
                .and_then(|value| value.get("retry_after_seconds"))
                .and_then(scalar_string_value)
        })
        .or_else(|| scalar_string(payload.get("retry_after_seconds")))
        .or_else(|| scalar_string(payload.pointer("/headers/retry-after")))
        .or_else(|| scalar_string(payload.pointer("/headers/Retry-After")))
        .or_else(|| {
            error
                .filter(|_| usage_limit)
                .and_then(usage_limit_retry_after)
        });

    Some(CodexEventFailure {
        kind,
        explicit_status,
        status,
        message,
        retry_after,
    })
}

pub(crate) fn first_retryable_failure(body: &[u8]) -> Option<CodexEventFailure> {
    first_event_failure(body).filter(CodexEventFailure::retryable)
}

pub(crate) fn first_event_failure(body: &[u8]) -> Option<CodexEventFailure> {
    for event in crate::anthropic::sse::parse_sse_events(body) {
        if event.data == "[DONE]" {
            continue;
        }
        let Ok(payload) = serde_json::from_str::<Value>(&event.data) else {
            continue;
        };
        if let Some(failure) = classify_event_failure(&payload) {
            return Some(failure);
        }
    }
    None
}

pub(crate) fn numeric_status(payload: &Value) -> Option<u64> {
    payload
        .get("status")
        .and_then(Value::as_u64)
        .or_else(|| payload.get("status_code").and_then(Value::as_u64))
}

fn scalar_string(value: Option<&Value>) -> Option<String> {
    value.and_then(scalar_string_value)
}

fn scalar_string_value(value: &Value) -> Option<String> {
    match value {
        Value::String(value) => Some(value.clone()),
        Value::Number(value) => Some(value.to_string()),
        _ => None,
    }
}

fn retryable_message(message: &str) -> bool {
    [
        "server error",
        "internal server error",
        "service unavailable",
        "bad gateway",
        "gateway timeout",
        "temporarily unavailable",
        "you can retry your request",
        "socket connection was closed unexpectedly",
        "connection closed unexpectedly",
        "operation timed out",
        "connection reset",
        "connection closed",
        "timed out",
        "timeout",
        "econnreset",
        "epipe",
        "etimedout",
        "und_err_socket",
        "fetch failed",
        "unexpected eof",
    ]
    .iter()
    .any(|needle| message.contains(needle))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_usage_limit_as_non_retryable_with_its_reset() {
        let failure = classify_event_failure(&serde_json::json!({
            "type": "error",
            "status": 429,
            "error": {
                "type": "usage_limit_reached",
                "message": "The usage limit has been reached",
                "plan_type": "plus",
                "resets_in_seconds": 3600
            }
        }))
        .unwrap();
        assert!(failure.is_usage_limit());
        assert!(!failure.retryable());
        assert_eq!(failure.status, 429);
        assert_eq!(failure.retry_after.as_deref(), Some("3600"));
    }

    #[test]
    fn usage_limit_reset_derives_from_absolute_time() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let error = serde_json::json!({ "type": "usage_limit_reached", "resets_at": now + 120 });
        let seconds: u64 = usage_limit_retry_after(&error).unwrap().parse().unwrap();
        assert!((119..=120).contains(&seconds));
    }

    #[test]
    fn throttling_is_not_a_usage_limit() {
        assert!(!is_usage_limit_error(&serde_json::json!({
            "code": "rate_limit_exceeded",
            "message": "Rate limit reached for requests"
        })));
        let failure = classify_event_failure(&serde_json::json!({
            "type": "response.failed",
            "response": {
                "error": { "code": "rate_limit_exceeded", "message": "Rate limit reached" }
            }
        }))
        .unwrap();
        assert_eq!(failure.kind, CodexFailureKind::RateLimit);
        assert!(failure.retryable());
    }

    #[test]
    fn classifies_retryable_failure_kinds() {
        let overload = classify_event_failure(&serde_json::json!({
            "type": "response.failed",
            "response": {"error": {"type": "overloaded_error", "message": "busy"}}
        }))
        .unwrap();
        assert_eq!(overload.status, 529);
        assert!(overload.retryable());
    }

    #[test]
    fn rate_limit_snapshots_are_always_telemetry() {
        assert!(
            classify_event_failure(&serde_json::json!({
                "type": "codex.rate_limits",
                "rate_limits": {"limit_reached": true},
                "credits": {"has_credits": false, "unlimited": false}
            }))
            .is_none()
        );
    }

    #[test]
    fn ignores_informational_and_permanent_events() {
        assert!(
            classify_event_failure(&serde_json::json!({
                "type": "codex.rate_limits",
                "rate_limits": {"limit_reached": false}
            }))
            .is_none()
        );
        let failure = classify_event_failure(&serde_json::json!({
            "type": "error",
            "error": {"status": 400, "message": "bad request"}
        }))
        .unwrap();
        assert!(!failure.retryable());
    }

    #[test]
    fn classifies_progress_and_terminal_semantics() {
        assert_eq!(
            classify_stream_event(&serde_json::json!({"type":"response.created"})),
            CodexStreamEventKind::Control
        );
        assert_eq!(
            classify_stream_event(&serde_json::json!({
                "type":"response.output_item.added",
                "item":{"type":"function_call"}
            })),
            CodexStreamEventKind::Structural
        );
        assert_eq!(
            classify_stream_event(&serde_json::json!({
                "type":"response.function_call_arguments.delta",
                "delta":"{}"
            })),
            CodexStreamEventKind::Semantic
        );
        assert_eq!(
            classify_stream_event(&serde_json::json!({"type":"response.incomplete"})),
            CodexStreamEventKind::TerminalFailure
        );
        assert_eq!(
            classify_stream_event(&serde_json::json!({
                "type":"response.completed",
                "error": null,
                "response": {
                    "status":"failed",
                    "error":{"status":400,"code":"invalid_prompt","message":"rejected"}
                }
            })),
            CodexStreamEventKind::TerminalFailure
        );
    }

    #[test]
    fn nested_response_error_survives_null_top_level_error() {
        let failure = classify_event_failure(&serde_json::json!({
            "type":"response.completed",
            "error": null,
            "response": {
                "status":"failed",
                "error":{"status":400,"code":"invalid_prompt","message":"nested rejection"}
            }
        }))
        .unwrap();
        assert_eq!(failure.client_status(), 400);
        assert_eq!(failure.client_error_type(), "invalid_request_error");
        assert_eq!(failure.message, "nested rejection");
        assert!(!failure.retryable());
    }

    #[test]
    fn completed_event_with_nested_error_is_not_success() {
        let payload = serde_json::json!({
            "type":"response.completed",
            "error": null,
            "response": {
                "status":"completed",
                "error":{"status":502,"code":"server_error","message":"late failure"}
            }
        });
        let failure = classify_event_failure(&payload).unwrap();
        assert_eq!(failure.client_status(), 502);
        assert!(failure.retryable());
        assert_eq!(
            classify_stream_event(&payload),
            CodexStreamEventKind::TerminalFailure
        );
    }

    #[test]
    fn completed_event_with_nested_null_error_is_success() {
        let payload = serde_json::json!({
            "type":"response.completed",
            "error": null,
            "response": {"status":"completed", "error":null}
        });
        assert!(classify_event_failure(&payload).is_none());
        assert_eq!(
            classify_stream_event(&payload),
            CodexStreamEventKind::TerminalSuccess
        );
    }

    #[test]
    fn native_fatal_codes_are_not_retried_without_numeric_status() {
        for (code, status, error_type) in [
            ("context_length_exceeded", 413, "request_too_large"),
            ("cyber_policy", 400, "invalid_request_error"),
            ("invalid_prompt", 400, "invalid_request_error"),
            ("bio_policy", 400, "invalid_request_error"),
            ("insufficient_quota", 429, "rate_limit_error"),
            ("usage_not_included", 403, "permission_error"),
        ] {
            let failure = classify_event_failure(&serde_json::json!({
                "type":"response.failed",
                "response":{"status":"failed","error":{"code":code,"message":"rejected"}}
            }))
            .unwrap();
            assert!(!failure.retryable(), "{code}");
            assert_eq!(failure.client_status(), status, "{code}");
            assert_eq!(failure.client_error_type(), error_type, "{code}");
        }
    }

    #[test]
    fn native_overload_codes_remain_retryable_without_numeric_status() {
        for code in ["server_is_overloaded", "slow_down"] {
            let failure = classify_event_failure(&serde_json::json!({
                "type":"response.failed",
                "response":{"status":"failed","error":{"code":code,"message":"busy"}}
            }))
            .unwrap();
            assert!(failure.retryable(), "{code}");
            assert_eq!(failure.client_status(), 529, "{code}");
            assert_eq!(failure.client_error_type(), "overloaded_error", "{code}");
        }
    }

    #[test]
    fn context_window_message_overrides_generic_upstream_400() {
        let failure = classify_event_failure(&serde_json::json!({
            "type":"error",
            "status":400,
            "error":{"type":"invalid_request_error","message":"input exceeds context window"}
        }))
        .unwrap();
        assert!(!failure.retryable());
        assert_eq!(failure.explicit_status, Some(400));
        assert_eq!(failure.client_status(), 413);
        assert_eq!(failure.client_error_type(), "request_too_large");
    }

    #[test]
    fn incomplete_policy_only_accepts_consistent_max_output_terminal() {
        let allowed = serde_json::json!({
            "type":"response.incomplete",
            "response": {
                "status":"incomplete",
                "error":null,
                "incomplete_details":{"reason":"max_output_tokens"}
            }
        });
        assert!(response_is_incomplete_terminal(&allowed));
        assert!(is_standard_max_output_tokens_incomplete(&allowed));
        let allowed_without_status = serde_json::json!({
            "type":"response.incomplete",
            "response": {
                "incomplete_details":{"reason":"max_output_tokens"}
            }
        });
        assert!(is_standard_max_output_tokens_incomplete(
            &allowed_without_status
        ));

        for rejected in [
            serde_json::json!({
                "type":"response.incomplete",
                "response":{"status":"incomplete","incomplete_details":{"reason":"content_filter"}}
            }),
            serde_json::json!({
                "type":"response.incomplete",
                "response":{"status":"incomplete","incomplete_details":{}}
            }),
            serde_json::json!({
                "type":"response.completed",
                "response":{"status":"completed","incomplete_details":{"reason":"max_output_tokens"}}
            }),
            serde_json::json!({
                "type":"response.incomplete",
                "response":{"status":null,"incomplete_details":{"reason":"max_output_tokens"}}
            }),
            serde_json::json!({
                "type":"response.incomplete",
                "response":{"status":123,"incomplete_details":{"reason":"max_output_tokens"}}
            }),
            serde_json::json!({
                "type":"response.incomplete",
                "response":{"status":"completed","incomplete_details":{"reason":"max_output_tokens"}}
            }),
            serde_json::json!({
                "type":"response.completed",
                "response":{"status":"completed","incomplete_details":{}}
            }),
        ] {
            assert!(response_is_incomplete_terminal(&rejected));
            assert!(!is_standard_max_output_tokens_incomplete(&rejected));
            assert!(classify_event_failure(&rejected).is_some());
        }
    }
}
