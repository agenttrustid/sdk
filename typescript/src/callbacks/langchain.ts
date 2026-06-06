/**
 * AgentTrust ID SDK — LangChainJS callback handler.
 *
 * Mirrors the Python `agenttrustid.callback.AgentTrustCallbackHandler` lifecycle:
 *
 *   handleToolStart  → AgentTrustGuard.check()  (throws if denied)
 *   handleToolEnd    → AgentTrustGuard.report() (success)
 *   handleToolError  → AgentTrustGuard.report() (failure)
 *   handleChainEnd   → AgentTrustGuard.flush()  (top-level only)
 *
 * `@langchain/core` is an OPTIONAL peer dependency. The module is loaded via
 * dynamic `require` so that consumers who don't use LangChain can still import
 * `@agenttrustid/sdk` without installing it. If LangChain is missing at runtime
 * and you instantiate `AgentTrustLangChainHandler`, the constructor throws a clear
 * error pointing at the install command.
 *
 * @example
 * ```typescript
 * import { AgentTrustClient, AgentTrustLangChainHandler } from '@agenttrustid/sdk';
 *
 * const client = AgentTrustClient.fromEnv();
 * const handler = new AgentTrustLangChainHandler(client, 'agent-id');
 * await agent.invoke({ input: '...' }, { callbacks: [handler] });
 * ```
 */

import { AgentTrustClient, AgentTrustGuard } from '../client';
import { AgentTrustError } from '../errors';

interface LangChainHandlerOptions {
  /** Session ID for correlation (auto-generated if not provided). */
  sessionId?: string;
  /** If true, denied actions raise AgentTrustError. Default: true. */
  blockOnDeny?: boolean;
  /** If true, allow actions when Guardian is unreachable. Default: false. */
  failOpen?: boolean;
  /** If true, include truncated tool inputs in pre-flight check. Default: false. */
  logInputs?: boolean;
  /** Max characters for tool input summaries. Default: 200. */
  maxInputChars?: number;
}

/**
 * Resolve the `BaseCallbackHandler` class from `@langchain/core` at runtime.
 *
 * Returns the constructor if LangChain is installed, or throws an AgentTrustError
 * with a clear install hint if not. We do this lazily so that
 * `import { AgentTrustLangChainHandler }` from the SDK succeeds in projects that
 * don't have LangChain installed.
 */
function loadBaseCallbackHandler(): unknown {
  try {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const mod = require('@langchain/core/callbacks/base');
    if (!mod || !mod.BaseCallbackHandler) {
      throw new Error('BaseCallbackHandler export not found');
    }
    return mod.BaseCallbackHandler;
  } catch (err) {
    throw new AgentTrustError(
      'AgentTrustLangChainHandler requires the optional peer dependency `@langchain/core`. Install it with: npm install @langchain/core',
      'PEER_DEPENDENCY_MISSING',
      { peer: '@langchain/core', original: err instanceof Error ? err.message : String(err) }
    );
  }
}

/**
 * Build the handler constructor lazily so it composes against the user's
 * installed `@langchain/core` `BaseCallbackHandler`.
 *
 * We can't `extends` a runtime-resolved class statically in TS, so we expose
 * a factory + a typed surface (`AgentTrustLangChainHandler`) that proxies to the
 * factory-produced instance. From the user's perspective:
 *
 *   const handler = new AgentTrustLangChainHandler(client, 'agent-id');
 *
 * works identically to a directly-extended class — the resulting object IS
 * an instance of `BaseCallbackHandler` (we set the prototype chain).
 */
let cachedHandlerClass: (new (
  client: AgentTrustClient,
  agentId: string,
  opts?: LangChainHandlerOptions
) => unknown) | null = null;

function buildHandlerClass(): new (
  client: AgentTrustClient,
  agentId: string,
  opts?: LangChainHandlerOptions
) => unknown {
  if (cachedHandlerClass) return cachedHandlerClass;

  const BaseCallbackHandler = loadBaseCallbackHandler() as new (
    input?: Record<string, unknown>
  ) => Record<string, unknown>;

  class AgentTrustLangChainHandlerImpl extends (BaseCallbackHandler as new (
    input?: Record<string, unknown>
  ) => Record<string, unknown>) {
    name = 'AgentTrustLangChainHandler';

    private guard: AgentTrustGuard;
    private logInputs: boolean;
    private maxInputChars: number;
    // Track tool call start times for duration calculation, keyed by run ID
    private toolStarts: Map<string, number> = new Map();

    constructor(client: AgentTrustClient, agentId: string, opts: LangChainHandlerOptions = {}) {
      super();
      this.guard = new AgentTrustGuard(client, agentId, {
        sessionId: opts.sessionId,
        blockOnDeny: opts.blockOnDeny ?? true,
        failOpen: opts.failOpen ?? false,
      });
      this.logInputs = opts.logInputs ?? false;
      this.maxInputChars = opts.maxInputChars ?? 200;
    }

    /**
     * LangChain calls this with `(tool, input, runId, parentRunId, tags, metadata, runName)`.
     * We pre-flight via Guardian. Throwing here aborts the tool call.
     */
    async handleToolStart(
      tool: { name?: string; id?: string[] } | Record<string, unknown>,
      input: string,
      runId: string,
      _parentRunId?: string,
      _tags?: string[],
      _metadata?: Record<string, unknown>,
      runName?: string
    ): Promise<void> {
      const toolName =
        (runName as string | undefined) ||
        (typeof (tool as { name?: string }).name === 'string'
          ? ((tool as { name?: string }).name as string)
          : undefined) ||
        // tool.id is the LangChain serialization path, last segment is tool name
        (Array.isArray((tool as { id?: string[] }).id)
          ? ((tool as { id?: string[] }).id as string[]).slice(-1)[0]
          : undefined) ||
        'unknown';

      // Prevent unbounded memory growth from orphaned tool starts
      if (this.toolStarts.size > 1000) {
        this.toolStarts.clear();
      }
      this.toolStarts.set(runId, Date.now());

      // Build input summary (privacy: truncated, optional)
      let inputSummary: string;
      if (this.logInputs) {
        const raw = input || '';
        inputSummary = raw.slice(0, this.maxInputChars);
      } else {
        // Just send char count, never content
        inputSummary = `[${(input || '').length} chars]`;
      }

      // AgentTrustGuard.check() throws AgentTrustError on deny (when blockOnDeny=true) or
      // when Guardian is unreachable and failOpen=false. Let it propagate —
      // LangChain treats a thrown handler as a tool error and aborts.
      await this.guard.check(toolName, inputSummary);
    }

    /**
     * Tool finished successfully. Record duration + report telemetry.
     */
    async handleToolEnd(
      _output: unknown,
      runId: string,
      _parentRunId?: string,
      _tags?: string[]
    ): Promise<void> {
      try {
        const start = this.toolStarts.get(runId);
        this.toolStarts.delete(runId);
        const durationMs = start ? Date.now() - start : 0;
        // We don't have the tool name here in older LangChain versions; use
        // 'unknown' if the framework didn't propagate it. Newer versions pass
        // it via `runName` on start (which we already used). To preserve it
        // across start→end we'd need a side-table; keep it simple — the
        // server correlates by sessionId + tool_end timing.
        this.guard.report('tool_end', true, durationMs);
      } catch (err) {
        // Telemetry failures must never crash the agent
        // eslint-disable-next-line no-console
        console.warn('[ATI] handleToolEnd telemetry error:', err);
      }
    }

    /**
     * Tool raised an error. Report failure telemetry.
     */
    async handleToolError(
      error: Error,
      runId: string,
      _parentRunId?: string,
      _tags?: string[]
    ): Promise<void> {
      try {
        const start = this.toolStarts.get(runId);
        this.toolStarts.delete(runId);
        const durationMs = start ? Date.now() - start : 0;
        const errorType =
          error && typeof error === 'object' && (error as { name?: string }).name
            ? ((error as { name?: string }).name as string)
            : 'Error';
        this.guard.report('tool_error', false, durationMs, errorType);
      } catch (err) {
        // eslint-disable-next-line no-console
        console.warn('[ATI] handleToolError telemetry error:', err);
      }
    }

    /**
     * Top-level chain end: flush pending telemetry.
     */
    async handleChainEnd(
      _outputs: Record<string, unknown>,
      _runId: string,
      parentRunId?: string,
      _tags?: string[]
    ): Promise<void> {
      // Only flush on top-level chain end (no parent) to avoid burst writes
      if (!parentRunId) {
        await this.guard.flush();
      }
    }

    /**
     * Manual flush — call when the agent is done if you don't use chains.
     */
    async flush(): Promise<void> {
      await this.guard.flush();
    }
  }

  cachedHandlerClass = AgentTrustLangChainHandlerImpl as unknown as new (
    client: AgentTrustClient,
    agentId: string,
    opts?: LangChainHandlerOptions
  ) => unknown;
  return cachedHandlerClass;
}

/**
 * `AgentTrustLangChainHandler` — Drop-in LangChainJS `BaseCallbackHandler` that
 * runs every tool call through the AgentTrust ID Guardian.
 *
 * Constructed as a regular class. The actual prototype chain is patched at
 * construction time to extend the user's installed
 * `@langchain/core/callbacks/base#BaseCallbackHandler`, so
 * `instanceof BaseCallbackHandler` returns true and LangChain accepts the
 * handler in its `callbacks` array.
 */
export class AgentTrustLangChainHandler {
  // The actual instance returned is an instance of the lazily-built class
  // that extends LangChain's BaseCallbackHandler. We use a constructor-return
  // trick to swap `this` for that instance. See: ECMAScript constructor
  // returning an explicit object overrides the implicit `this`.
  constructor(client: AgentTrustClient, agentId: string, opts?: LangChainHandlerOptions) {
    const Cls = buildHandlerClass();
    return new Cls(client, agentId, opts) as unknown as AgentTrustLangChainHandler;
  }

  // Type-only declarations so TS sees the public surface. These are never
  // actually executed — the real instance comes from the LangChain-extended
  // class above.
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  handleToolStart!: (
    tool: Record<string, unknown>,
    input: string,
    runId: string,
    parentRunId?: string,
    tags?: string[],
    metadata?: Record<string, unknown>,
    runName?: string
  ) => Promise<void>;
  handleToolEnd!: (
    output: unknown,
    runId: string,
    parentRunId?: string,
    tags?: string[]
  ) => Promise<void>;
  handleToolError!: (
    error: Error,
    runId: string,
    parentRunId?: string,
    tags?: string[]
  ) => Promise<void>;
  handleChainEnd!: (
    outputs: Record<string, unknown>,
    runId: string,
    parentRunId?: string,
    tags?: string[]
  ) => Promise<void>;
  flush!: () => Promise<void>;
  name!: string;
}

