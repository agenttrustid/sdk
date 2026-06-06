"""AgentTrust SDK A2A (Agent-to-Agent) Task Management"""

import uuid
from typing import Dict, List, Optional

from .models import A2ATask, A2AMessageTask


class A2AAPI:
    """A2A task management API.

    Enables agent-to-agent communication through the A2A protocol.
    Tasks are dispatched via JSON-RPC through the /a2a endpoint.

    Example:
        # Send a task from one agent to another
        task = client.a2a.send_task(
            source_agent_id="agent-123",
            target_agent_id="agent-456",
            message="Summarize the latest security report",
        )

        # Check task status
        task = client.a2a.get_task(task.id)

        # Cancel if needed
        client.a2a.cancel_task(task.id)
    """

    def __init__(self, http_client):
        self._http = http_client

    def _jsonrpc_request(self, method: str, params: dict, path: str = "/a2a") -> dict:
        """Send a JSON-RPC request to an A2A endpoint.

        Args:
            method: JSON-RPC method name (e.g., "tasks/send")
            params: Method parameters
            path: Endpoint to POST to. Defaults to the shared ``/a2a``
                endpoint; ``message/send`` targets the per-agent endpoint
                ``/a2a/agents/{agent_id}`` so the server resolves the actor
                from the path.

        Returns:
            The "result" field from the JSON-RPC response
        """
        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params,
        }
        response = self._http.post(path, payload)
        # JSON-RPC responses have the result nested under "result"
        if "result" in response:
            return response["result"]
        return response

    def send_task(
        self,
        source_agent_id: str,
        target_agent_id: str,
        message: str,
        metadata: Optional[Dict] = None,
    ) -> A2ATask:
        """
        Send a task from one agent to another.

        Args:
            source_agent_id: ID of the agent sending the task
            target_agent_id: ID of the agent receiving the task
            message: Task message/instruction for the target agent
            metadata: Optional metadata to attach to the task

        Returns:
            A2ATask with the created task details
        """
        params = {
            "source_agent_id": source_agent_id,
            "target_agent_id": target_agent_id,
            "message": message,
        }
        if metadata:
            params["metadata"] = metadata

        result = self._jsonrpc_request("tasks/send", params)
        return A2ATask.from_dict(result)

    def get_task(self, task_id: str) -> A2ATask:
        """
        Get the current status and details of a task.

        Args:
            task_id: ID of the task to retrieve

        Returns:
            A2ATask with current task state
        """
        result = self._jsonrpc_request("tasks/get", {"task_id": task_id})
        return A2ATask.from_dict(result)

    def cancel_task(self, task_id: str) -> A2ATask:
        """
        Cancel a pending or in-progress task.

        Args:
            task_id: ID of the task to cancel

        Returns:
            A2ATask with updated (cancelled) status
        """
        result = self._jsonrpc_request("tasks/cancel", {"task_id": task_id})
        return A2ATask.from_dict(result)

    def send_message(
        self,
        agent_id: str,
        text: str,
        message_id: Optional[str] = None,
        task_id: Optional[str] = None,
    ) -> A2AMessageTask:
        """
        Send a message to an agent using the A2A v1.0 ``message/send`` method.

        Dispatches a JSON-RPC ``message/send`` call to the target agent's
        per-agent endpoint ``/a2a/agents/{agent_id}`` (mirroring the other
        SDKs) so the server resolves the actor from the path. The message
        follows the v1.0 schema with a text part. A new ``messageId`` is
        generated when one is not supplied. If ``task_id`` is given, the
        message is attached to that existing task.

        Args:
            agent_id: ID of the target agent.
            text: The text content of the message.
            message_id: Optional client-supplied message ID (a UUID is
                generated when omitted).
            task_id: Optional existing task ID to continue.

        Returns:
            A2AMessageTask parsed from the v1.0 Task result
            ``{id, contextId, status: {state, timestamp}, history?, artifacts?}``.
        """
        message: Dict = {
            "role": "user",
            "parts": [{"kind": "text", "text": text}],
            "messageId": message_id or str(uuid.uuid4()),
        }
        if task_id:
            message["taskId"] = task_id

        # Post to the per-agent endpoint; the server authorizes message/send
        # from the path agent, not a params field. Params carry only the
        # message, matching the Go/TS/Java/Rust SDKs.
        params = {"message": message}
        result = self._jsonrpc_request(
            "message/send", params, path=f"/a2a/agents/{agent_id}"
        )
        return A2AMessageTask.from_dict(result)
