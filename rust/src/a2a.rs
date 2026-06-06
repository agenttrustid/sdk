//! Agent-to-Agent (A2A) task dispatch via JSON-RPC 2.0.
//!
//! The A2A protocol lets one ATI-registered agent send a task to another. All
//! calls are made through the gateway's `/a2a` JSON-RPC endpoint and Guardian
//! checks each call.
//!
//! # Example
//!
//! ```rust,no_run
//! use agenttrustid::{AgentTrustClient, SendTaskRequest};
//! use serde_json::json;
//!
//! let client = AgentTrustClient::builder().build().unwrap();
//!
//! let task = client.a2a().create_task(&SendTaskRequest {
//!     source_agent_id: "agent-a".to_string(),
//!     target_agent_id: "agent-b".to_string(),
//!     message: json!({"text": "summarize"}),
//! }).unwrap();
//!
//! println!("Task: {}", task.id);
//! ```

use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::client::AgentTrustClient;
use crate::error::{AgentTrustError, Result};
use crate::models::{A2ATask, SendTaskRequest, V1Task};

/// Provides A2A (agent-to-agent) task dispatch operations.
///
/// Obtained via [`AgentTrustClient::a2a()`].
pub struct A2A<'a> {
    pub(crate) client: &'a AgentTrustClient,
    pub(crate) request_id: AtomicU64,
}

#[derive(Debug, Serialize)]
struct JsonRpcRequest<P: Serialize> {
    jsonrpc: &'static str,
    method: String,
    params: P,
    id: String,
}

#[derive(Debug, Deserialize)]
struct JsonRpcResponse {
    #[serde(default)]
    result: Option<Value>,
    #[serde(default)]
    error: Option<JsonRpcError>,
}

#[derive(Debug, Deserialize)]
struct JsonRpcError {
    #[serde(default)]
    code: Option<i64>,
    #[serde(default)]
    message: Option<String>,
}

#[derive(Debug, Serialize)]
struct SendTaskParams<'a> {
    source_agent_id: &'a str,
    target_agent_id: &'a str,
    message: &'a Value,
}

#[derive(Debug, Serialize)]
struct TaskIdParams<'a> {
    id: &'a str,
}

#[derive(Debug, Serialize)]
struct TaskListParams {
    limit: u32,
}

#[derive(Debug, Serialize)]
struct MessagePart<'a> {
    kind: &'static str,
    text: &'a str,
}

#[derive(Debug, Serialize)]
struct V1Message<'a> {
    role: &'static str,
    parts: Vec<MessagePart<'a>>,
    #[serde(rename = "messageId")]
    message_id: String,
    #[serde(rename = "taskId", skip_serializing_if = "Option::is_none")]
    task_id: Option<String>,
}

#[derive(Debug, Serialize)]
struct SendMessageParams<'a> {
    message: V1Message<'a>,
}

impl<'a> A2A<'a> {
    fn next_id(&self) -> String {
        let id = self.request_id.fetch_add(1, Ordering::SeqCst) + 1;
        id.to_string()
    }

    fn rpc<P: Serialize>(&self, method: &str, params: P) -> Result<Value> {
        self.rpc_at("/a2a", method, params)
    }

    /// Issue a JSON-RPC 2.0 call to a specific gateway path. Used to target the
    /// per-agent A2A endpoint for A2A v1.0 `message/send`.
    fn rpc_at<P: Serialize>(&self, path: &str, method: &str, params: P) -> Result<Value> {
        let req = JsonRpcRequest {
            jsonrpc: "2.0",
            method: method.to_string(),
            params,
            id: self.next_id(),
        };

        let resp: JsonRpcResponse = self.client.request("POST", path, Some(req))?;
        if let Some(err) = resp.error {
            return Err(AgentTrustError::Api {
                message: err.message.unwrap_or_else(|| "A2A RPC error".to_string()),
                code: format!("A2A_ERROR_{}", err.code.unwrap_or(0)),
                status: 400,
            });
        }
        resp.result.ok_or_else(|| AgentTrustError::Api {
            message: "A2A RPC missing result".to_string(),
            code: "A2A_NO_RESULT".to_string(),
            status: 500,
        })
    }

    /// Create (send) a new A2A task to a target agent.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use agenttrustid::{AgentTrustClient, SendTaskRequest};
    /// # use serde_json::json;
    /// # let client = AgentTrustClient::builder().build().unwrap();
    /// let task = client.a2a().create_task(&SendTaskRequest {
    ///     source_agent_id: "a".to_string(),
    ///     target_agent_id: "b".to_string(),
    ///     message: json!({"text": "hi"}),
    /// }).unwrap();
    /// ```
    pub fn create_task(&self, req: &SendTaskRequest) -> Result<A2ATask> {
        let params = SendTaskParams {
            source_agent_id: &req.source_agent_id,
            target_agent_id: &req.target_agent_id,
            message: &req.message,
        };
        let value = self.rpc("tasks/send", params)?;
        let task: A2ATask = serde_json::from_value(value)?;
        Ok(task)
    }

    /// Send an A2A v1.0 message to `agent_id` via JSON-RPC `message/send`.
    ///
    /// Posts to the target agent's per-agent endpoint
    /// (`/a2a/agents/{agent_id}`) with params
    /// `{ message: { role: "user", parts: [{ kind: "text", text }], messageId, taskId? } }`
    /// and returns the resulting A2A v1.0 [`V1Task`].
    ///
    /// `message_id` defaults to a generated UUID when `None`. `task_id`, when
    /// supplied, continues an existing task/turn.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use agenttrustid::AgentTrustClient;
    /// # let client = AgentTrustClient::builder().build().unwrap();
    /// let task = client
    ///     .a2a()
    ///     .send_message("agent-b", "summarize this", None, None)
    ///     .unwrap();
    /// println!("task {} -> {}", task.id, task.status.state);
    /// ```
    pub fn send_message(
        &self,
        agent_id: &str,
        text: &str,
        message_id: Option<String>,
        task_id: Option<String>,
    ) -> Result<V1Task> {
        let message_id = message_id.unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
        let params = SendMessageParams {
            message: V1Message {
                role: "user",
                parts: vec![MessagePart {
                    kind: "text",
                    text,
                }],
                message_id,
                task_id,
            },
        };
        let path = format!("/a2a/agents/{}", agent_id);
        let value = self.rpc_at(&path, "message/send", params)?;
        let task: V1Task = serde_json::from_value(value)?;
        Ok(task)
    }

    /// Get the current state of an A2A task.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use agenttrustid::AgentTrustClient;
    /// # let client = AgentTrustClient::builder().build().unwrap();
    /// let task = client.a2a().get_task("task-1").unwrap();
    /// println!("status: {}", task.status);
    /// ```
    pub fn get_task(&self, task_id: &str) -> Result<A2ATask> {
        let value = self.rpc("tasks/get", TaskIdParams { id: task_id })?;
        let task: A2ATask = serde_json::from_value(value)?;
        Ok(task)
    }

    /// Cancel a running A2A task.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use agenttrustid::AgentTrustClient;
    /// # let client = AgentTrustClient::builder().build().unwrap();
    /// let task = client.a2a().cancel_task("task-1").unwrap();
    /// assert_eq!(task.status, "cancelled");
    /// ```
    pub fn cancel_task(&self, task_id: &str) -> Result<A2ATask> {
        let value = self.rpc("tasks/cancel", TaskIdParams { id: task_id })?;
        let task: A2ATask = serde_json::from_value(value)?;
        Ok(task)
    }

    /// List recent A2A tasks visible to the caller.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use agenttrustid::AgentTrustClient;
    /// # let client = AgentTrustClient::builder().build().unwrap();
    /// let tasks = client.a2a().list_tasks().unwrap();
    /// println!("{} tasks", tasks.len());
    /// ```
    pub fn list_tasks(&self) -> Result<Vec<A2ATask>> {
        let value = self.rpc("tasks/list", TaskListParams { limit: 50 })?;
        let tasks_value = value
            .get("tasks")
            .cloned()
            .unwrap_or_else(|| Value::Array(Vec::new()));
        let tasks: Vec<A2ATask> = serde_json::from_value(tasks_value)?;
        Ok(tasks)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::AgentTrustError;
    use mockito::{Matcher, Server};
    use serde_json::json;

    #[test]
    fn test_create_task_success() {
        let mut srv = Server::new();
        let mock = srv
            .mock("POST", "/a2a")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{"jsonrpc":"2.0","id":"1","result":{
                    "id":"task-1","source_agent_id":"a","target_agent_id":"b","status":"pending"
                }}"#,
            )
            .create();

        let client = AgentTrustClient::builder()
            .base_url(&srv.url())
            .build()
            .unwrap();
        let task = client
            .a2a()
            .create_task(&SendTaskRequest {
                source_agent_id: "a".to_string(),
                target_agent_id: "b".to_string(),
                message: json!({"text": "hi"}),
            })
            .unwrap();
        assert_eq!(task.id, "task-1");
        assert_eq!(task.status, "pending");
        mock.assert();
    }

    #[test]
    fn test_send_message_success() {
        let mut srv = Server::new();
        let mock = srv
            .mock("POST", "/a2a/agents/agent-b")
            .match_body(Matcher::AllOf(vec![
                Matcher::PartialJsonString(r#"{"method":"message/send"}"#.to_string()),
                Matcher::PartialJsonString(
                    r#"{"params":{"message":{"role":"user","parts":[{"kind":"text","text":"hello"}],"messageId":"msg-1"}}}"#
                        .to_string(),
                ),
            ]))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{"jsonrpc":"2.0","id":"1","result":{
                    "id":"task-9",
                    "contextId":"ctx-1",
                    "status":{"state":"completed","timestamp":"2026-06-02T00:00:00Z"},
                    "artifacts":[{"name":"reply"}]
                }}"#,
            )
            .create();

        let client = AgentTrustClient::builder()
            .base_url(&srv.url())
            .build()
            .unwrap();
        let task = client
            .a2a()
            .send_message("agent-b", "hello", Some("msg-1".to_string()), None)
            .unwrap();
        assert_eq!(task.id, "task-9");
        assert_eq!(task.context_id, "ctx-1");
        assert_eq!(task.status.state, "completed");
        assert_eq!(task.artifacts.unwrap().len(), 1);
        mock.assert();
    }

    #[test]
    fn test_send_message_rpc_error() {
        let mut srv = Server::new();
        let mock = srv
            .mock("POST", "/a2a/agents/missing")
            .with_status(200)
            .with_body(
                r#"{"jsonrpc":"2.0","id":"1","error":{"code":-32601,"message":"unknown agent"}}"#,
            )
            .create();

        let client = AgentTrustClient::builder()
            .base_url(&srv.url())
            .build()
            .unwrap();
        let err = client
            .a2a()
            .send_message("missing", "hi", None, None)
            .unwrap_err();
        match err {
            AgentTrustError::Api { code, .. } => assert!(code.contains("A2A_ERROR_")),
            other => panic!("expected Api error, got {:?}", other),
        }
        mock.assert();
    }

    #[test]
    fn test_get_task_rpc_error() {
        let mut srv = Server::new();
        let mock = srv
            .mock("POST", "/a2a")
            .with_status(200)
            .with_body(
                r#"{"jsonrpc":"2.0","id":"1","error":{"code":-32601,"message":"not found"}}"#,
            )
            .create();

        let client = AgentTrustClient::builder()
            .base_url(&srv.url())
            .build()
            .unwrap();
        let err = client.a2a().get_task("missing").unwrap_err();
        match err {
            AgentTrustError::Api { code, .. } => assert!(code.contains("A2A_ERROR_")),
            other => panic!("expected Api error, got {:?}", other),
        }
        mock.assert();
    }

    #[test]
    fn test_cancel_task_http_500() {
        let mut srv = Server::new();
        let mock = srv
            .mock("POST", "/a2a")
            .with_status(500)
            .with_body(r#"{"message":"server failure"}"#)
            .create();

        let client = AgentTrustClient::builder()
            .base_url(&srv.url())
            .build()
            .unwrap();
        let err = client.a2a().cancel_task("task-1").unwrap_err();
        match err {
            AgentTrustError::Api { status, .. } => assert_eq!(status, 500),
            other => panic!("expected Api error, got {:?}", other),
        }
        mock.assert();
    }

    #[test]
    fn test_list_tasks_validation_error() {
        let mut srv = Server::new();
        let mock = srv
            .mock("POST", "/a2a")
            .with_status(200)
            .with_body(
                r#"{"jsonrpc":"2.0","id":"1","error":{"code":-32602,"message":"bad query"}}"#,
            )
            .create();

        let client = AgentTrustClient::builder()
            .base_url(&srv.url())
            .build()
            .unwrap();
        let err = client.a2a().list_tasks().unwrap_err();
        assert!(matches!(err, AgentTrustError::Api { .. }));
        mock.assert();
    }
}
