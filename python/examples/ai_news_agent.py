#!/usr/bin/env python3
"""
AI News Agent — Live AI News Briefing

An agent that searches for real AI news using DuckDuckGo,
summarizes it with the configured Anthropic model, and delivers
briefings to the AgentTrust ID dashboard and email.

Secured by AgentTrust ID — every tool call is
checked by Guardian and reported to the audit trail.

Usage:
    # 1. Start AgentTrust ID services
    docker compose up -d

    # 2. Create an API key from the dashboard Settings page (http://localhost:3002/settings)

    # 3. Install dependencies
    pip install duckduckgo-search schedule

    # 4. Set environment variables
    export AGENTTRUST_URL=http://localhost:8080
    export AGENTTRUST_API_KEY=sk_live_...
    export ANTHROPIC_API_KEY=sk-ant-...   # optional, for AI summaries
    export NEWS_INTERVAL_HOURS=24         # optional, default 24

    # 5. Run the agent
    python examples/ai_news_agent.py

What happens:
    1. Agent registers with AgentTrust ID and is issued an opaque agent token (`at_...`)
    2. Before each tool call, ATI's Fast Guard checks authorization
    3. Agent searches DuckDuckGo for real AI news (top 10 results)
    4. Agent uses the configured Anthropic model to analyze,
       summarize, and score each article for credibility
    5. Briefing is posted to the dashboard alerts page
    6. Email is sent if SMTP is configured
    7. Telemetry is reported to AgentTrust ID audit trail
    8. Agent sleeps and repeats on schedule
    9. View results at http://localhost:3002/alerts and /audit
"""

import os
import sys
import time
import json
import urllib.request
import urllib.error
from datetime import datetime, timezone

# Add parent to path for local development
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from agenttrustid import AgentTrustClient
from agenttrustid.guard import AgentTrustGuard


# ──── Tools (real implementations) ────

def web_search(query: str) -> list:
    """Search the web using DuckDuckGo (no API key needed)."""
    try:
        from ddgs import DDGS
    except ImportError:
        try:
            from duckduckgo_search import DDGS
        except ImportError:
            print("  ERROR: pip install ddgs")
            return []

    try:
        results = []
        with DDGS() as ddgs:
            for r in ddgs.news(query, max_results=10):
                results.append({
                    "title": r.get("title", ""),
                    "source": r.get("source", ""),
                    "snippet": r.get("body", ""),
                    "date": r.get("date", ""),
                    "url": r.get("url", ""),
                })
        return results
    except Exception as e:
        print(f"  Search error: {e}")
        return []


def summarize_text(text: str) -> str:
    """Use the configured Anthropic model to analyze and summarize text,
    including credibility scoring based on degree of freedom analysis.
    Falls back to full text if anthropic is not installed."""
    try:
        import anthropic
        client = anthropic.Anthropic()
        response = client.messages.create(
            model="claude-opus-4-6",
            max_tokens=16000,
            thinking={
                "type": "adaptive",
                "budget_tokens": 10000,
            },
            messages=[{
                "role": "user",
                "content": (
                    "Analyze the following AI news items. For each item:\n\n"
                    "1. **Title** — The article headline\n"
                    "2. **Source** — The news outlet or publisher\n"
                    "3. **Summary** — A complete 2-3 sentence summary explaining what is "
                    "actually happening (do not truncate)\n"
                    "4. **Credibility Score (1-10)** — Rate each item based on a "
                    "\"degree of freedom\" analysis:\n"
                    "   - How well are claims supported by verifiable facts?\n"
                    "   - Is the reporting based on scientific evidence or peer-reviewed research?\n"
                    "   - How reliable and reputable is the source?\n"
                    "   - Is the reasoning logically consistent, or does it rely on speculation?\n"
                    "   - Score: 1 = pure speculation/clickbait, 10 = well-sourced factual reporting\n\n"
                    "After analyzing all items, provide a **Key Takeaways** section with "
                    "3-4 bullet points summarizing the most important developments.\n\n"
                    f"News items:\n{text}"
                ),
            }],
        )
        # Extended thinking responses may contain thinking blocks; extract the text block
        for block in response.content:
            if block.type == "text":
                return block.text
        return response.content[0].text
    except ImportError:
        print("  [Note: Install 'anthropic' package for AI summaries. Using full text.]")
        return text
    except Exception as e:
        print(f"  [Anthropic API error: {e}. Using full text.]")
        return text


def deliver_to_dashboard(summary: str, article_count: int):
    """Post the briefing to the AgentTrust ID notification service (dashboard alerts + email)."""
    notification_url = os.getenv("NOTIFICATION_URL", "http://localhost:8088")
    payload = json.dumps({
        "severity": "info",
        "title": f"AI News Briefing — {datetime.now().strftime('%b %d, %Y %H:%M')}",
        "message": summary,
        "event_count": article_count,
        "send_email": True,
    }).encode()

    try:
        req = urllib.request.Request(
            f"{notification_url}/api/v1/alerts",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        urllib.request.urlopen(req, timeout=5)
        print("  Briefing posted to dashboard + email sent.")
    except Exception as e:
        print(f"  Could not post to dashboard: {e} (non-fatal)")


# ──── Agent State ────

_client = None
_guard = None
_agent_id = None


def setup():
    """One-time: connect to ATI, register agent, initialize Guard."""
    global _client, _guard, _agent_id

    base_url = os.getenv("AGENTTRUST_URL", "http://localhost:8080")
    print(f"[1/3] Connecting to AgentTrust ID gateway at {base_url}...")
    _client = AgentTrustClient(base_url=base_url)

    api_key = os.getenv("AGENTTRUST_API_KEY", "")
    if api_key:
        _client.set_api_key(api_key)
        print(f"  Using API key: {api_key[:12]}...")
    else:
        print("  WARNING: No AGENTTRUST_API_KEY set. Set one from the dashboard Settings page.")

    print("[2/3] Registering agent with ATI...")
    try:
        agent = _client.agents.create(
            name="ai-news-live",
            framework="anthropic",
            capabilities=["web_search", "summarize"],
        )
        _agent_id = agent.id
        print(f"  Agent ID: {_agent_id}")
        print(f"  Framework: {agent.framework} | Status: {agent.status.value}")
    except Exception as e:
        print(f"  Agent creation: {e}")
        # Fallback: find existing agent by name via REST API
        try:
            req = urllib.request.Request(
                f"{base_url}/api/v1/agents",
                headers={"X-API-Key": api_key} if api_key else {},
            )
            resp = urllib.request.urlopen(req, timeout=5)
            data = json.loads(resp.read())
            agents_list = data.get("agents", data) if isinstance(data, dict) else data
            match = [a for a in agents_list if a.get("name") == "ai-news-live" and a.get("status") == "active"]
            if match:
                _agent_id = match[0]["id"]
                print(f"  Found existing agent: {_agent_id}")
            else:
                print("  ERROR: Could not create or find active agent.")
                return False
        except Exception as e2:
            print(f"  ERROR: Could not find agent: {e2}")
            return False

    print("[3/3] Initializing AgentTrust ID Guardian security...")
    _guard = AgentTrustGuard(
        _client,
        agent_id=_agent_id,
        block_on_deny=True,
        fail_open=True,
    )
    print("  Guardian initialized. Agent is live.\n")
    return True


def run_news_cycle():
    """One cycle: search real news, summarize, deliver."""
    global _guard, _agent_id

    cycle_time = datetime.now().strftime("%Y-%m-%d %H:%M")
    print("=" * 60)
    print(f"  AI News Briefing — {cycle_time}")
    print("=" * 60)
    print()

    search_queries = [
        "AI artificial intelligence news today",
        "AI startup funding",
    ]

    all_articles = []
    for query in search_queries:
        # Guard: check before tool call
        start_time = time.time()
        try:
            _guard.check("web_search", input_summary=f"query: {query[:50]}")
            print(f"  Guardian approved: web_search")
        except Exception as e:
            print(f"  Guardian denied: {e}")
            continue

        # Execute real web search
        results = web_search(query)
        duration_ms = int((time.time() - start_time) * 1000)

        # Guard: report after tool call
        _guard.report("web_search", success=len(results) > 0, duration_ms=duration_ms)
        print(f"  Found {len(results)} articles for: {query}")
        all_articles.extend(results)
        time.sleep(2)  # Avoid DuckDuckGo rate limits

    # Deduplicate by title
    seen = set()
    unique_articles = []
    for article in all_articles:
        if article["title"] and article["title"] not in seen:
            seen.add(article["title"])
            unique_articles.append(article)

    print(f"\n  Total unique articles: {len(unique_articles)}")

    if not unique_articles:
        print("  No articles found. Skipping summary.")
        _guard.close()
        return

    # Generate summary
    print("\n  Generating summary...")

    start_time = time.time()
    try:
        _guard.check("summarize", input_summary=f"[{len(unique_articles)} articles]")
        print(f"  Guardian approved: summarize")
    except Exception as e:
        print(f"  Guardian denied summarize: {e}")
        _guard.close()
        return

    articles_text = "\n".join(
        f"- {a['title']} ({a['source']}): {a['snippet']}"
        for a in unique_articles
    )

    summary = summarize_text(articles_text)
    duration_ms = int((time.time() - start_time) * 1000)
    _guard.report("summarize", success=True, duration_ms=duration_ms)

    # Print results
    print("\n" + "=" * 60)
    print("  BRIEFING")
    print("=" * 60)
    print()
    print(summary)
    print()
    print("-" * 60)
    print(f"Sources: {len(unique_articles)} articles | Agent: {_agent_id}")
    print("-" * 60)

    # Deliver to dashboard + email
    deliver_to_dashboard(summary, len(unique_articles))

    # Flush telemetry
    _guard.close()
    print("Telemetry flushed to AgentTrust ID audit trail.\n")


def main():
    """Entry point: setup once, then run on schedule."""
    try:
        import schedule
    except ImportError:
        print("ERROR: Install schedule: pip install schedule")
        sys.exit(1)

    if not setup():
        sys.exit(1)

    # Run immediately
    run_news_cycle()

    # Schedule recurring runs
    interval_hours = int(os.getenv("NEWS_INTERVAL_HOURS", "24"))
    schedule.every(interval_hours).hours.do(run_news_cycle)

    next_run = datetime.now().strftime("%H:%M")
    print(f"Agent live. Next cycle in {interval_hours} hours. Ctrl+C to stop.")
    print(f"  Dashboard: http://localhost:3002/alerts")
    print(f"  Audit trail: http://localhost:3002/audit")

    try:
        while True:
            schedule.run_pending()
            time.sleep(60)
    except KeyboardInterrupt:
        print("\nAgent stopped.")


if __name__ == "__main__":
    main()
