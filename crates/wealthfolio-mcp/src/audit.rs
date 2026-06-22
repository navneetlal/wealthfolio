//! Audit hook contract. Hosts wire their SQLite repository in; this crate
//! only defines the entry shape and when entries are emitted.

use crate::auth::ActorKind;

/// How a tool call ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditOutcome {
    Success,
    Denied,
    Error,
}

impl AuditOutcome {
    /// Stable string used in audit rows.
    pub fn as_str(&self) -> &'static str {
        match self {
            AuditOutcome::Success => "success",
            AuditOutcome::Denied => "denied",
            AuditOutcome::Error => "error",
        }
    }
}

/// One audit row for an MCP tool invocation.
#[derive(Debug, Clone)]
pub struct McpAuditEntry {
    /// MCP session id (`Mcp-Session-Id` header), or `"stateless"`.
    pub session_id: String,
    pub actor_kind: ActorKind,
    pub actor_fingerprint: String,
    pub tool: String,
    /// Canonical scope strings granted to the caller at call time.
    pub scopes: Vec<String>,
    /// Tool arguments AFTER per-tool sanitization — safe to persist.
    pub args_summary: serde_json::Value,
    pub outcome: AuditOutcome,
    pub error_message: Option<String>,
}

/// Persistence hook implemented by runtime hosts.
///
/// `record` must be cheap to call from the request path; the handler
/// invokes it via `tokio::spawn` so slow storage never blocks responses.
#[async_trait::async_trait]
pub trait AuditSink: Send + Sync {
    async fn record(&self, entry: McpAuditEntry);
}
