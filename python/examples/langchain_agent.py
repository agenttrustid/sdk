"""
AgentTrust ID + LangChain Integration Example

Every tool call is checked by Guardian before execution and reported to the audit trail.

Prerequisites:
    pip install agenttrustid[langchain] langchain langchain-community
    export AGENTTRUST_API_KEY=sk_live_xxx
    export AGENTTRUST_URL=http://localhost:8080
"""

import os
from agenttrustid import AgentTrustClient
from agenttrustid.callback import AgentTrustCallbackHandler

# 1. Connect to AgentTrust ID
client = AgentTrustClient.from_env()

# 2. Register your agent (one-time)
agent = client.agents.create(name="demo-langchain-agent", framework="LANGCHAIN")
print(f"Agent registered: {agent.id}")

# 3. Create callback handler
handler = AgentTrustCallbackHandler(
    client,
    agent_id=agent.id,
    block_on_deny=True,   # Denied actions raise AgentTrustError
    fail_open=False,       # Block if Guardian is unreachable
    log_inputs=False,      # Never send tool inputs (privacy)
)

# 4. Use with any LangChain agent
# from langchain.agents import create_tool_calling_agent, AgentExecutor
# agent_executor = AgentExecutor(agent=..., tools=[...])
# result = agent_executor.invoke(
#     {"input": "Search for the latest AI news"},
#     config={"callbacks": [handler]},
# )

# 5. When done, flush telemetry
handler.close()
print("Done. Check the audit trail in the AgentTrust ID dashboard.")
