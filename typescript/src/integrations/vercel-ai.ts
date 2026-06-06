/**
 * AgentTrust SDK — Vercel AI SDK middleware integration.
 *
 * Wraps a Vercel AI `LanguageModelV1` so every tool call the model emits is
 * pre-flighted through the AgentTrust ID Guardian (Fast Guard). Denied tool calls are
 * stripped from the model output and replaced with a denial text, so the
 * downstream agent loop sees the model "decided not to use the tool" rather
 * than hitting an exception that would abort streaming.
 *
 * `ai` is an OPTIONAL peer dependency. The module is loaded lazily via
 * `require` so SDK consumers who don't use Vercel AI can still
 * `import { withAgentTrustVercelAI } from '@agenttrustid/sdk'`.
 *
 * @example
 * ```typescript
 * import { openai } from '@ai-sdk/openai';
 * import { AgentTrustClient, withAgentTrustVercelAI } from '@agenttrustid/sdk';
 *
 * const client = AgentTrustClient.fromEnv();
 * const model = withAgentTrustVercelAI(openai('gpt-4o'), { client, agentId: 'agent-1' });
 * const { text } = await generateText({ model, tools, prompt: '...' });
 * ```
 *
 * @remarks
 * Built against `ai` v4 / `LanguageModelV1Middleware`. The middleware shape
 * has historically been re-shuffled between Vercel AI SDK majors — if you're
 * on a newer version and the import fails, fall back to using
 * `AgentTrustGuard` directly inside your `tool({ execute })` function body until
 * this integration is updated.
 */

import { AgentTrustClient, AgentTrustGuard } from '../client';
import { AgentTrustError } from '../errors';

interface WithAgentTrustOptions {
  client: AgentTrustClient;
  agentId: string;
  /** Session ID for correlation (auto-generated if not provided). */
  sessionId?: string;
  /** If true, denied tool calls are stripped from model output. Default: true. */
  blockOnDeny?: boolean;
  /** If true, allow tool calls when Guardian is unreachable. Default: false. */
  failOpen?: boolean;
  /** Optional custom model id for the wrapped model. */
  modelId?: string;
  /** Optional custom provider id for the wrapped model. */
  providerId?: string;
}

/**
 * Lazily resolve `wrapLanguageModel` from the user's installed `ai` package.
 * Throws an AgentTrustError with install hint if `ai` is not installed.
 */
function loadWrapLanguageModel(): (args: {
  model: unknown;
  middleware: unknown;
  modelId?: string;
  providerId?: string;
}) => unknown {
  try {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const ai = require('ai');
    // Prefer stable name, fall back to experimental_ for older v4 betas.
    const fn = ai.wrapLanguageModel || ai.experimental_wrapLanguageModel;
    if (typeof fn !== 'function') {
      throw new Error('wrapLanguageModel export not found in `ai`');
    }
    return fn as (args: {
      model: unknown;
      middleware: unknown;
      modelId?: string;
      providerId?: string;
    }) => unknown;
  } catch (err) {
    throw new AgentTrustError(
      'withAgentTrustVercelAI requires the optional peer dependency `ai` (Vercel AI SDK v4+). Install it with: npm install ai',
      'PEER_DEPENDENCY_MISSING',
      { peer: 'ai', original: err instanceof Error ? err.message : String(err) }
    );
  }
}

interface ToolCall {
  toolCallType: 'function';
  toolCallId: string;
  toolName: string;
  args: string;
}

interface GenerateResult {
  text?: string;
  toolCalls?: ToolCall[];
  finishReason?: string;
  [key: string]: unknown;
}

/**
 * Build a `LanguageModelV1Middleware` that pre-flights every tool call.
 *
 * Implementation strategy:
 *
 *   - `wrapGenerate` runs `doGenerate()`, then iterates `result.toolCalls`,
 *     calls `guard.check()` for each, drops denied ones, and reports
 *     telemetry. The mutated result is returned to the caller.
 *
 *   - `wrapStream` proxies the stream, intercepting `tool-call` parts and
 *     replacing denied ones with a `text-delta` part explaining the denial,
 *     keeping the SSE wire format valid for downstream consumers.
 */
function buildMiddleware(opts: WithAgentTrustOptions): Record<string, unknown> {
  const guard = new AgentTrustGuard(opts.client, opts.agentId, {
    sessionId: opts.sessionId,
    blockOnDeny: opts.blockOnDeny ?? true,
    failOpen: opts.failOpen ?? false,
  });

  /**
   * Check a single tool call. Returns `{ allowed, reason? }`. Never throws —
   * we want to translate denials into structured output, not exceptions,
   * because Vercel AI's tool loop swallows errors awkwardly.
   */
  async function checkToolCall(
    call: ToolCall
  ): Promise<{ allowed: boolean; reason?: string }> {
    try {
      // Per project policy, never log raw tool input — send a length summary.
      const inputSummary = `[${(call.args || '').length} chars]`;
      const ok = await guard.check(call.toolName, inputSummary);
      return { allowed: ok };
    } catch (err) {
      if (err instanceof AgentTrustError && err.code === 'ACTION_DENIED') {
        return { allowed: false, reason: err.message };
      }
      if (err instanceof AgentTrustError && err.code === 'ELEVATION_REQUIRED') {
        return { allowed: false, reason: `Elevation required: ${err.message}` };
      }
      // Guardian unreachable + failOpen=false → AgentTrustError with code GUARDIAN_UNAVAILABLE.
      // Per blockOnDeny we treat this as a deny.
      if (err instanceof AgentTrustError) {
        return { allowed: false, reason: err.message };
      }
      // Unknown error — fail closed unless explicitly fail-open.
      if (opts.failOpen) {
        return { allowed: true };
      }
      return {
        allowed: false,
        reason: `Guardian check failed: ${err instanceof Error ? err.message : String(err)}`,
      };
    }
  }

  return {
    middlewareVersion: 'v1',

    async wrapGenerate({
      doGenerate,
    }: {
      doGenerate: () => Promise<GenerateResult>;
    }): Promise<GenerateResult> {
      const startTime = Date.now();
      const result = await doGenerate();

      if (!result.toolCalls || result.toolCalls.length === 0) {
        return result;
      }

      const allowedCalls: ToolCall[] = [];
      const denials: string[] = [];

      for (const call of result.toolCalls) {
        const { allowed, reason } = await checkToolCall(call);
        if (allowed) {
          allowedCalls.push(call);
          // Best-effort telemetry — tool actually ran outside the wrapper, so
          // duration is "time-to-decision" not tool execution time.
          guard.report(call.toolName, true, Date.now() - startTime);
        } else {
          denials.push(`${call.toolName}: ${reason || 'denied by Guardian'}`);
          guard.report(call.toolName, false, Date.now() - startTime, 'AGENTTRUST_DENIED');
        }
      }

      // Replace tool calls in-place. If everything got denied, we surface a
      // text explanation so the agent loop can react gracefully.
      const next: GenerateResult = { ...result, toolCalls: allowedCalls };
      if (denials.length > 0 && allowedCalls.length === 0) {
        next.text = `${next.text || ''}\n\n[AgentTrust ID Guardian denied tool call(s): ${denials.join('; ')}]`.trim();
        next.finishReason = 'stop';
      }
      return next;
    },

    async wrapStream({
      doStream,
    }: {
      doStream: () => Promise<{ stream: ReadableStream<unknown>; [k: string]: unknown }>;
    }): Promise<{ stream: ReadableStream<unknown>; [k: string]: unknown }> {
      const result = await doStream();
      const startTime = Date.now();

      // Tee a transform stream that filters tool-call parts.
      const transformed = result.stream.pipeThrough(
        new TransformStream<unknown, unknown>({
          async transform(chunk, controller) {
            const part = chunk as { type?: string } & ToolCall;
            if (part && part.type === 'tool-call') {
              const { allowed, reason } = await checkToolCall({
                toolCallType: 'function',
                toolCallId: part.toolCallId,
                toolName: part.toolName,
                args: part.args,
              });
              if (allowed) {
                guard.report(part.toolName, true, Date.now() - startTime);
                controller.enqueue(chunk);
              } else {
                guard.report(part.toolName, false, Date.now() - startTime, 'AGENTTRUST_DENIED');
                controller.enqueue({
                  type: 'text-delta',
                  textDelta: `[AgentTrust ID Guardian denied tool '${part.toolName}': ${reason || 'denied'}]`,
                });
              }
              return;
            }
            controller.enqueue(chunk);
          },
        })
      );

      return { ...result, stream: transformed };
    },
  };
}

/**
 * Wrap a Vercel AI `LanguageModelV1` so every tool call is checked by ATI
 * Guardian before the agent loop executes it.
 */
export function withAgentTrust<TModel = unknown>(model: TModel, options: WithAgentTrustOptions): TModel {
  if (!options || !options.client || !options.agentId) {
    throw new AgentTrustError(
      'withAgentTrustVercelAI requires { client, agentId } in options',
      'INVALID_OPTIONS'
    );
  }
  const wrapLanguageModel = loadWrapLanguageModel();
  const middleware = buildMiddleware(options);
  return wrapLanguageModel({
    model,
    middleware,
    modelId: options.modelId,
    providerId: options.providerId,
  }) as TModel;
}

// Legacy alias.
export { withAgentTrust as withATI };
