#!/usr/bin/env npx tsx
/**
 * AI Security Threats Agent — Live Security Briefing
 *
 * An agent that searches for real AI security threats, analyzes them with the
 * configured model, and delivers briefings to the AgentTrust ID dashboard and email.
 *
 * Secured by AgentTrust ID — every tool call is checked by Guardian
 * and reported to the audit trail.
 *
 * Usage:
 *   # 1. Start AgentTrust ID services
 *   docker compose up -d
 *
 *   # 2. Create an API key from the dashboard Settings page
 *
 *   # 3. Install dependencies
 *   cd sdk/typescript && npm install
 *
 *   # 4. Set environment variables
 *   export AGENTTRUST_URL=http://localhost:8080
 *   export AGENTTRUST_API_KEY=sk_live_...
 *   export OPENAI_API_KEY=sk-...   # optional, for AI analysis
 *
 *   # 5. Run the agent
 *   npx tsx examples/security_threats_agent.ts
 *
 * What happens:
 *   1. Agent registers with AgentTrust ID and is issued an opaque agent token (`at_...`)
 *   2. Before each tool call, ATI's Guardian checks authorization
 *   3. Agent searches DuckDuckGo for real AI security news
 *   4. Agent uses OpenAI to analyze threats (or falls back to excerpts)
 *   5. Briefing is posted to the dashboard alerts page + email
 *   6. Telemetry is reported to AgentTrust ID audit trail
 *   7. Agent sleeps and repeats every 24 hours
 *   8. View results at http://localhost:3002/alerts and /audit
 */

import { AgentTrustClient, AgentTrustGuard } from '../src';

// ──── Tools (real implementations) ────

async function searchThreats(query: string): Promise<
  Array<{
    title: string;
    source: string;
    snippet: string;
    date: string;
    url: string;
  }>
> {
  try {
    const { search } = await import('duckduckgo-search');
    const results = await search(query, { maxResults: 10 });
    return results.map((r: any) => ({
      title: r.title || '',
      source: r.url ? new URL(r.url).hostname : '',
      snippet: r.description || r.body || '',
      date: new Date().toISOString().split('T')[0],
      url: r.url || '',
    }));
  } catch (error: unknown) {
    // Fallback: use node fetch to search DuckDuckGo HTML
    try {
      const encoded = encodeURIComponent(query);
      const resp = await fetch(
        `https://html.duckduckgo.com/html/?q=${encoded}`,
        {
          headers: {
            'User-Agent':
              'Mozilla/5.0 (compatible; ATI-Agent/1.0)',
          },
        }
      );
      const html = await resp.text();
      // Extract results from HTML
      const results: Array<{
        title: string;
        source: string;
        snippet: string;
        date: string;
        url: string;
      }> = [];
      const titleRegex =
        /<a[^>]*class="result__a"[^>]*>(.*?)<\/a>/gs;
      const snippetRegex =
        /<a[^>]*class="result__snippet"[^>]*>(.*?)<\/a>/gs;
      let titleMatch;
      let snippetMatch;
      while (
        (titleMatch = titleRegex.exec(html)) &&
        results.length < 10
      ) {
        snippetMatch = snippetRegex.exec(html);
        results.push({
          title: titleMatch[1].replace(/<[^>]+>/g, '').trim(),
          source: 'DuckDuckGo',
          snippet: snippetMatch
            ? snippetMatch[1].replace(/<[^>]+>/g, '').trim()
            : '',
          date: new Date().toISOString().split('T')[0],
          url: '',
        });
      }
      return results;
    } catch (fallbackErr) {
      const msg =
        error instanceof Error ? error.message : String(error);
      console.log(`  Search error: ${msg}`);
      return [];
    }
  }
}

async function analyzeWithAI(text: string): Promise<string> {
  try {
    const { default: OpenAI } = await import('openai');
    const client = new OpenAI();

    const response = await client.chat.completions.create({
      model: 'gpt-5.2',
      max_completion_tokens: 4000,
      messages: [
        {
          role: 'system',
          content:
            'You are an elite AI security analyst. Provide thorough, actionable security briefings. Never truncate or abbreviate your analysis.',
        },
        {
          role: 'user',
          content: `Analyze the following AI security threat reports. For each item:

1. **Title** — The article headline
2. **Source** — The news outlet or publisher
3. **Summary** — A complete 2-3 sentence summary explaining what is actually happening (do not truncate)
4. **Credibility Score (1-10)** — Rate each item based on a "degree of freedom" analysis:
   - How well are claims supported by verifiable facts?
   - Is the reporting based on scientific evidence or peer-reviewed research?
   - How reliable and reputable is the source?
   - Is the reasoning logically consistent, or does it rely on speculation?
   - Score: 1 = pure speculation/clickbait, 10 = well-sourced factual reporting

After analyzing all items, provide a **Key Takeaways** section with 3-4 bullet points summarizing the most critical security developments and recommended mitigations.

Threat reports:
${text}`,
        },
      ],
    });

    return response.choices[0]?.message?.content || text;
  } catch (error: unknown) {
    const msg = error instanceof Error ? error.message : String(error);
    if (
      msg.includes('Cannot find module') ||
      msg.includes('MODULE_NOT_FOUND')
    ) {
      console.log(
        '  [Note: Install "openai" package for AI analysis. Using excerpts.]'
      );
    } else {
      console.log(`  [OpenAI API error: ${msg}. Using excerpts.]`);
    }
    return text;
  }
}

async function deliverToDashboard(
  summary: string,
  threatCount: number
): Promise<void> {
  const notificationUrl =
    process.env.NOTIFICATION_URL || 'http://localhost:8088';
  try {
    const resp = await fetch(`${notificationUrl}/api/v1/alerts`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        severity: 'warning',
        title: `Security Briefing — ${new Date().toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' })} ${new Date().toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' })}`,
        message: summary,
        event_count: threatCount,
        send_email: true,
      }),
    });
    if (resp.ok) {
      console.log('  Briefing posted to dashboard + email sent.');
    } else {
      console.log(
        `  Dashboard post failed: ${resp.status} (non-fatal)`
      );
    }
  } catch (error) {
    const msg = error instanceof Error ? error.message : String(error);
    console.log(`  Could not post to dashboard: ${msg} (non-fatal)`);
  }
}

// ──── Agent State ────

let client: AgentTrustClient;
let guard: AgentTrustGuard;
let agentId: string;

async function setup(): Promise<boolean> {
  const atiUrl =
    process.env.AGENTTRUST_URL ||
    process.env.AGENTTRUST_BASE_URL ||
    'http://localhost:8080';
  console.log(`[1/3] Connecting to AgentTrust ID gateway at ${atiUrl}...`);
  client = new AgentTrustClient({ baseUrl: atiUrl });

  const apiKey = process.env.AGENTTRUST_API_KEY || '';
  if (apiKey) {
    client.setApiKey(apiKey);
    console.log(`  Using API key: ${apiKey.slice(0, 12)}...`);
  } else {
    console.log(
      '  WARNING: No AGENTTRUST_API_KEY set. Set one from the dashboard Settings page.'
    );
  }

  console.log('[2/3] Registering agent with ATI...');
  try {
    const agent = await client.agents.create({
      name: 'security-threats-monitor',
      framework: 'openai',
      capabilities: ['threat_search', 'analyze'],
    });
    agentId = agent.id;
    console.log(`  Agent ID: ${agentId}`);
    console.log(`  Status: ${agent.status ?? 'pending'}`);
  } catch (error: unknown) {
    const msg = error instanceof Error ? error.message : String(error);
    console.log(`  Agent creation: ${msg}`);
    // Find existing agent
    try {
      const agents = await client.agents.list();
      const match = agents.find(
        (a: any) => a.name === 'security-threats-monitor'
      );
      if (match) {
        agentId = match.id;
        console.log(`  Found existing agent: ${agentId}`);
      } else {
        console.log('  ERROR: Could not create or find agent.');
        return false;
      }
    } catch {
      console.log('  ERROR: Could not create or find agent.');
      return false;
    }
  }

  console.log('[3/3] Initializing AgentTrust ID Guardian security...');
  guard = new AgentTrustGuard(client, agentId, {
    blockOnDeny: true,
    failOpen: true,
  });
  console.log('  Guardian initialized. Agent is live.\n');
  return true;
}

async function runSecurityCycle(): Promise<void> {
  const divider = '='.repeat(60);
  const cycleTime = new Date().toLocaleString();
  console.log(divider);
  console.log(`  Security Threats Briefing — ${cycleTime}`);
  console.log(divider);
  console.log();

  const queries = [
    'AI security threats vulnerabilities today',
    'AI agent cybersecurity risks',
  ];

  const allThreats: Array<{
    title: string;
    source: string;
    snippet: string;
    date: string;
    url: string;
  }> = [];

  for (const query of queries) {
    const startTime = Date.now();
    try {
      await guard.check('threat_search', `query: ${query.slice(0, 50)}`);
      console.log('  Guardian approved: threat_search');
    } catch (error: unknown) {
      const msg = error instanceof Error ? error.message : String(error);
      console.log(`  Guardian denied: ${msg}`);
      continue;
    }

    const results = await searchThreats(query);
    const durationMs = Date.now() - startTime;
    guard.report('threat_search', results.length > 0, durationMs);
    console.log(`  Found ${results.length} threats for: ${query}`);
    allThreats.push(...results);
    await new Promise((r) => setTimeout(r, 2000)); // Avoid DuckDuckGo rate limits
  }

  // Deduplicate
  const seen = new Set<string>();
  const uniqueThreats = allThreats.filter((t) => {
    if (!t.title || seen.has(t.title)) return false;
    seen.add(t.title);
    return true;
  });

  console.log(`\n  Total unique threats: ${uniqueThreats.length}`);

  if (uniqueThreats.length === 0) {
    console.log('  No threats found. Skipping analysis.');
    await guard.flush();
    return;
  }

  // Generate analysis
  console.log('\n  Generating security analysis...');

  const startTime = Date.now();
  try {
    await guard.check('analyze', `[${uniqueThreats.length} threats]`);
    console.log('  Guardian approved: analyze');
  } catch (error: unknown) {
    const msg = error instanceof Error ? error.message : String(error);
    console.log(`  Guardian denied analyze: ${msg}`);
    await guard.flush();
    return;
  }

  const threatsText = uniqueThreats
    .map((t) => `- ${t.title} (${t.source}): ${t.snippet}`)
    .join('\n');

  const analysis = await analyzeWithAI(threatsText);
  const durationMs = Date.now() - startTime;
  guard.report('analyze', true, durationMs);

  // Print results
  console.log('\n' + divider);
  console.log('  SECURITY BRIEFING');
  console.log(divider);
  console.log();
  console.log(analysis);
  console.log();
  console.log('-'.repeat(60));
  console.log(
    `Threats scanned: ${uniqueThreats.length} | Agent: ${agentId}`
  );
  console.log('-'.repeat(60));

  // Deliver to dashboard + email
  await deliverToDashboard(analysis, uniqueThreats.length);

  // Flush telemetry
  await guard.flush();
  console.log('Telemetry flushed to AgentTrust ID audit trail.\n');
}

async function main(): Promise<void> {
  if (!(await setup())) {
    process.exit(1);
  }

  // Run immediately
  await runSecurityCycle();

  // Schedule recurring runs
  const intervalHours = parseInt(
    process.env.NEWS_INTERVAL_HOURS || '24',
    10
  );
  const intervalMs = intervalHours * 60 * 60 * 1000;

  console.log(
    `Agent live. Next cycle in ${intervalHours} hours. Ctrl+C to stop.`
  );
  console.log('  Dashboard: http://localhost:3002/alerts');
  console.log('  Audit trail: http://localhost:3002/audit');

  const interval = setInterval(async () => {
    try {
      await runSecurityCycle();
    } catch (error) {
      console.error('Cycle error:', error);
    }
  }, intervalMs);

  // Graceful shutdown
  process.on('SIGINT', () => {
    clearInterval(interval);
    console.log('\nAgent stopped.');
    process.exit(0);
  });
}

main().catch(console.error);
