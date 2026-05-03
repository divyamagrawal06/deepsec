// Preflight checks run before we spin up sandboxes or agent SDKs.
//
// The motivation: when env vars are missing, the failure surfaces deep in
// upstream code — Anthropic SDK throws "API key not found" with no hint
// the issue is on the orchestrator host, the Vercel SDK errors look like
// auth problems somewhere remote, and the sandbox firewall happily emits
// `{ allow: { host: [] } }` with no transform rule so requests later 401
// from upstream as if it were a model issue. Each variant has cost the
// human time before, so we trade ~20 lines for a clear message up front.

import { existsSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

// Linkable URL — printed in error messages so users can paste the
// URL into a browser instead of hunting through the repo. Points at
// the rendered `main` version on github.com so it works whether the
// CLI was invoked from inside the source repo, from an installed
// package, or in CI.
const SETUP_DOC_URL = "https://github.com/vercel-labs/deepsec/blob/main/docs/vercel-setup.md";

// Vercel AI Gateway endpoints. The Anthropic adapter is at the root; the
// OpenAI-compatible adapter is at /v1 (codex appends /responses to it).
const GATEWAY_ANTHROPIC_BASE_URL = "https://ai-gateway.vercel.sh";
const GATEWAY_OPENAI_BASE_URL = "https://ai-gateway.vercel.sh/v1";

/**
 * If the user set `AI_GATEWAY_API_KEY`, expand it into the four env vars
 * the agent SDKs actually read. Lets a user run with a single token
 * instead of duplicating it across `ANTHROPIC_AUTH_TOKEN` /
 * `OPENAI_API_KEY` (the gateway accepts the same token for both).
 *
 * Existing values always win — this only fills in what's missing, so a
 * user who has set, say, `ANTHROPIC_BASE_URL=https://api.anthropic.com`
 * for direct-to-provider access doesn't get silently rerouted.
 *
 * Call this once at CLI startup (after dotenv loads .env.local), before
 * any module reads these vars.
 */
export function applyAiGatewayDefaults(): void {
  const key = process.env.AI_GATEWAY_API_KEY;
  if (!key) return;
  if (!process.env.ANTHROPIC_AUTH_TOKEN) process.env.ANTHROPIC_AUTH_TOKEN = key;
  if (!process.env.OPENAI_API_KEY) process.env.OPENAI_API_KEY = key;
  if (!process.env.ANTHROPIC_BASE_URL) process.env.ANTHROPIC_BASE_URL = GATEWAY_ANTHROPIC_BASE_URL;
  if (!process.env.OPENAI_BASE_URL) process.env.OPENAI_BASE_URL = GATEWAY_OPENAI_BASE_URL;
}

function isCodex(agentType: string | undefined): boolean {
  return agentType === "codex";
}

/**
 * Detect a local Claude Code subscription login. The Claude Agent SDK
 * spawns the `claude` CLI as a subprocess, so any auth that CLI accepts
 * (Linux file-based credentials, a long-lived OAuth token from
 * `claude setup-token`) lets the SDK run without an API key on the
 * orchestrator's env.
 *
 * macOS users authenticate Claude Code via Keychain — there's no file
 * marker we can read without spawning `security` and racing against
 * permission prompts. For that path we ask the user to run
 * `claude setup-token` once and put the resulting token in
 * `CLAUDE_CODE_OAUTH_TOKEN`; that's the cross-platform escape hatch the
 * SDK already understands.
 *
 * Only relevant for non-sandbox runs. The sandbox path runs in a worker
 * VM that has no claude binary and no keychain access; it must ship a
 * real API token through the firewall header rewrite, so this helper is
 * never consulted there.
 */
function hasLocalClaudeLogin(): boolean {
  if (process.env.CLAUDE_CODE_OAUTH_TOKEN) return true;
  const claudeHome = process.env.CLAUDE_HOME || join(homedir(), ".claude");
  return existsSync(join(claudeHome, ".credentials.json"));
}

/**
 * Detect a local Codex subscription login. `codex login` writes
 * `auth.json` into `$CODEX_HOME` (defaulting to `~/.codex`) on every
 * platform deepsec supports — Codex doesn't use Keychain on macOS — so
 * a single file check suffices.
 *
 * Same non-sandbox restriction as the Claude variant: the codex binary
 * lives on the orchestrator's host, not in the sandbox worker VM.
 */
function hasLocalCodexLogin(): boolean {
  const codexHome = process.env.CODEX_HOME || join(homedir(), ".codex");
  return existsSync(join(codexHome, "auth.json"));
}

// Built-in backends we know how to credential-check. Agents registered
// via plugins (deepsec.config.ts → plugins: [{ agents: [...] }]) handle
// their own credential resolution, so we skip the check for anything
// other than these.
const KNOWN_BACKENDS = new Set<string>(["claude-agent-sdk", "codex"]);

/**
 * Verify the orchestrator has an AI credential the chosen agent can use.
 * Throws with a concrete pointer at .env.local when it doesn't — the
 * sandbox path brokers credentials via firewall header injection, but
 * that only works if the orchestrator actually has a token to inject.
 *
 * Pass `inSandbox: true` from sandbox commands. Subscription auth (a
 * local `claude login`) is only honored when this is false — the
 * sandbox worker has no `claude` CLI and no Keychain, so it must ship a
 * real API token through the firewall header rewrite.
 *
 * Skipped for plugin-supplied agents (`agentType` not in `KNOWN_BACKENDS`):
 * those backends own their credential story. Tests use this to plug in a
 * stub agent without setting fake env vars.
 */
export function assertAgentCredential(
  agentType: string | undefined,
  options: { inSandbox?: boolean } = {},
): void {
  if (agentType !== undefined && !KNOWN_BACKENDS.has(agentType)) return;

  const anthropic = process.env.ANTHROPIC_AUTH_TOKEN;
  const openai = process.env.OPENAI_API_KEY;

  if (isCodex(agentType)) {
    // Codex prefers OPENAI_API_KEY; AI Gateway issues a single token that
    // authenticates both backends, so an ANTHROPIC token is also accepted.
    if (openai || anthropic) return;
    if (!options.inSandbox && hasLocalCodexLogin()) return;
    const codexSubscriptionHint = options.inSandbox
      ? ""
      : `\n` +
        `  Local-only alternative — use your Codex / ChatGPT subscription:\n` +
        `    Run \`codex login\` on this machine. deepsec mirrors the\n` +
        `    resulting ~/.codex/auth.json into a per-invocation tempdir\n` +
        `    so concurrent batches don't stomp on the session DB.\n`;
    throw new Error(
      `Missing AI credentials for --agent codex.\n` +
        `\n` +
        `  Quickest fix — get a Vercel AI Gateway key (covers both Claude\n` +
        `  and Codex with one token) and add it to .env.local:\n` +
        `\n` +
        `      AI_GATEWAY_API_KEY=vck_…\n` +
        `\n` +
        `  Or set OPENAI_API_KEY directly.\n` +
        codexSubscriptionHint +
        `\n` +
        `  Full setup: ${SETUP_DOC_URL}`,
    );
  }

  if (anthropic) return;
  if (!options.inSandbox && hasLocalClaudeLogin()) return;
  const subscriptionHint = options.inSandbox
    ? ""
    : `\n` +
      `  Local-only alternative — use your Claude Code subscription:\n` +
      `    Linux: \`claude login\` writes ~/.claude/.credentials.json and\n` +
      `      deepsec picks it up automatically.\n` +
      `    macOS: run \`claude setup-token\` and add the printed token to\n` +
      `      .env.local as CLAUDE_CODE_OAUTH_TOKEN=… (the Keychain login\n` +
      `      that Claude Code uses isn't readable from a Node process).\n`;
  throw new Error(
    `Missing AI credentials for --agent ${agentType ?? "claude-agent-sdk"}.\n` +
      `\n` +
      `  Quickest fix — get a Vercel AI Gateway key (covers both Claude\n` +
      `  and Codex with one token) and add it to .env.local:\n` +
      `\n` +
      `      AI_GATEWAY_API_KEY=vck_…\n` +
      `\n` +
      `  Or set ANTHROPIC_AUTH_TOKEN directly.\n` +
      subscriptionHint +
      `\n` +
      `  Full setup: ${SETUP_DOC_URL}`,
  );
}

/**
 * Verify the orchestrator has Vercel Sandbox credentials. Inside a Vercel
 * deployment OIDC is automatic; locally the user runs `vercel link` +
 * `vercel env pull` to land VERCEL_OIDC_TOKEN in .env.local, OR sets the
 * three explicit access-token env vars.
 */
export function assertSandboxCredential(): void {
  const oidc = process.env.VERCEL_OIDC_TOKEN;
  if (oidc) return;

  const token = process.env.VERCEL_TOKEN;
  const teamId = process.env.VERCEL_TEAM_ID;
  const projectId = process.env.VERCEL_PROJECT_ID;
  if (token && teamId && projectId) return;

  const missing: string[] = [];
  if (!token) missing.push("VERCEL_TOKEN");
  if (!teamId) missing.push("VERCEL_TEAM_ID");
  if (!projectId) missing.push("VERCEL_PROJECT_ID");

  throw new Error(
    `Missing Vercel Sandbox credentials.\n` +
      `\n` +
      `  Recommended: run these to populate VERCEL_OIDC_TOKEN in .env.local:\n` +
      `\n` +
      `      npx vercel link\n` +
      `      npx vercel env pull\n` +
      `\n` +
      `  Alternative — access-token mode: set ${missing.join(", ")}.\n` +
      `\n` +
      `  Full setup: ${SETUP_DOC_URL}`,
  );
}
