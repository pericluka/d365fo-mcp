#!/usr/bin/env node
// A stand-in for the Claude Code CLI in the dry run of evals/run.mjs. It takes the same arguments, starts the MCP server
// of --mcp-config, replays the tool calls of the scripted transcript in EVAL_TRANSCRIPT against it and prints what
// claude -p --output-format stream-json --verbose prints. No model is involved: the dry run checks the harness, its
// isolation flags and the grading, not Claude. Besides calls and answer a transcript may hold usage (tokens to
// report), extraServers and extraTools (more than the fake's server in the init message), pauseMs (a wait after it),
// forgeResults (answer the calls without the server, like another server of the same name), stop (end with that result
// subtype and no answer, like --max-turns) and splitUtf8 (write the result line in two parts inside a UTF-8 character).
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const emit = (message) => process.stdout.write(`${JSON.stringify(message)}\n`);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** Write a message in two parts that split its first multibyte character, with a pause so they arrive as two chunks. */
async function emitSplit(message) {
  const bytes = Buffer.from(`${JSON.stringify(message)}\n`, "utf8");
  const at = bytes.findIndex((b) => b >= 0x80);
  if (at < 0) throw new Error("fake claude: splitUtf8 needs an answer with a character outside ASCII");
  await new Promise((resolve) => process.stdout.write(bytes.subarray(0, at + 1), resolve));
  await sleep(100);
  process.stdout.write(bytes.subarray(at + 1));
}

/** The answer of a run that could not start, in the shape the real CLI uses for errors. */
function fail(message) {
  emit({ type: "result", subtype: "success", is_error: true, num_turns: 0, result: message, total_cost_usd: 0, usage: { input_tokens: 0, output_tokens: 0 } });
  process.exit(1);
}

// ---------------------------------------------------------------- Arguments

const SWITCHES = new Set(["-p", "--print", "--verbose", "--strict-mcp-config", "--no-session-persistence", "--disable-slash-commands"]);
const flags = {};
const positional = [];
const argv = process.argv.slice(2);
for (let i = 0; i < argv.length; i++) {
  if (SWITCHES.has(argv[i])) flags[argv[i]] = true;
  else if (argv[i].startsWith("--")) flags[argv[i]] = argv[++i];
  else positional.push(argv[i]);
}

// What keeps a real run away from the user's own configuration, in particular a live F&O server in it. The harness
// must pass all of it, so the dry run fails when one goes missing.
const REQUIRED = {
  "-p": true, "--output-format": "stream-json", "--verbose": true, "--strict-mcp-config": true, "--tools": "", "--setting-sources": "",
  "--disable-slash-commands": true, "--permission-mode": "dontAsk", "--no-session-persistence": true,
};
const missing = Object.entries(REQUIRED).filter(([flag, value]) => flags[flag] !== value).map(([flag, value]) => (value === true ? flag : `${flag} ${JSON.stringify(value)}`));
if (!flags["--mcp-config"]) missing.push("--mcp-config");
if (!positional[0]) missing.push("the prompt");
if (process.env.CLAUDECODE !== undefined) missing.push("CLAUDECODE removed from the environment");
for (const name of ["CLAUDE_CODE_DISABLE_CLAUDE_MDS", "CLAUDE_CODE_DISABLE_AUTO_MEMORY"]) if (process.env[name] !== "1") missing.push(`${name}=1`);
if (missing.length) fail(`fake claude: the harness did not pass ${missing.join(", ")}`);

let transcript;
try {
  transcript = JSON.parse(process.env.EVAL_TRANSCRIPT ?? "");
} catch {
  fail("fake claude: EVAL_TRANSCRIPT must hold the transcript as JSON");
}
const list = (value) => (value ?? "").split(/[\s,]+/).filter(Boolean);
const allowed = list(flags["--allowedTools"]);
const disallowed = list(flags["--disallowedTools"]);

// ---------------------------------------------------------------- MCP servers

const { mcpServers } = JSON.parse(readFileSync(flags["--mcp-config"], "utf8"));
// The server loads .env from the folder of its package.json. The project's .env points at a real F&O, so the harness
// must start a copy of dist that sits in a folder of its own. The dry run fails when it starts the project's dist.
const project = resolve(fileURLToPath(new URL("..", import.meta.url)));
for (const [name, config] of Object.entries(mcpServers)) {
  const home = resolve(dirname(dirname(config.args?.[0] ?? "")));
  if (home === project || !existsSync(join(home, "package.json")) || existsSync(join(home, ".env"))) {
    fail(`fake claude: MCP server ${name} runs ${config.args?.[0]}, not a copy of dist in a folder of its own without a .env`);
  }
}
const servers = [];
for (const [name, config] of Object.entries(mcpServers)) {
  const transport = new StdioClientTransport({ command: config.command, args: config.args, env: config.env, stderr: "ignore" });
  const client = new Client({ name: "fake-claude", version: "0.0.0" });
  await client.connect(transport);
  const { tools } = await client.listTools();
  servers.push({ name, client, tools: tools.map((t) => `mcp__${name}__${t.name}`) });
}
const closeAll = () => Promise.all(servers.map((s) => s.client.close().catch(() => {})));
process.on("SIGTERM", async () => {
  await closeAll();
  process.exit(143);
});

const offered = servers.flatMap((s) => s.tools).filter((t) => !disallowed.includes(t));
const model = flags["--model"] ?? "dry-run";
emit({
  type: "system", subtype: "init", cwd: process.cwd(), session_id: "dry-run", model, permissionMode: flags["--permission-mode"],
  tools: [...offered, ...(transcript.extraTools ?? [])],
  mcp_servers: [...servers.map((s) => ({ name: s.name, status: "connected" })), ...(transcript.extraServers ?? []).map((name) => ({ name, status: "connected" }))],
});
// Gives the harness time to stop a run whose init it refuses before any call goes out.
if (transcript.pauseMs) await sleep(transcript.pauseMs);

// ---------------------------------------------------------------- Transcript

let turns = 0;
let read = 0; // characters of tool results, for a rough token count
for (const [tool, input] of transcript.calls ?? []) {
  turns++;
  const id = `toolu_dry_${turns}`;
  const server = servers[0];
  const name = `mcp__${server.name}__${tool}`;
  emit({ type: "assistant", message: { role: "assistant", content: [{ type: "tool_use", id, name, input }] } });
  let text;
  let isError = true;
  if (!offered.includes(name)) text = `Error: No such tool available: ${name}`;
  else if (!allowed.includes(name)) text = `Permission to use ${name} has been denied.`; // what dontAsk does with a tool that is not allowed
  else if (transcript.forgeResults) {
    text = JSON.stringify({ collection: input.entity, returned: 0, hasMore: false, rows: [] });
    isError = false;
  } else {
    try {
      const result = await server.client.callTool({ name: tool, arguments: input });
      text = result.content.map((c) => c.text).join("\n");
      isError = !!result.isError;
    } catch (error) {
      text = `Error: ${error.message}`;
    }
  }
  read += text.length;
  emit({ type: "user", message: { role: "user", content: [{ type: "tool_result", tool_use_id: id, content: [{ type: "text", text }], is_error: isError }] } });
}
// A run cut off by --max-turns or --max-budget-usd has no final answer. Its result carries no result text either.
if (!transcript.stop) {
  turns++;
  emit({ type: "assistant", message: { role: "assistant", content: [{ type: "text", text: transcript.answer }] } });
}
await closeAll();

const inputTokens = transcript.usage?.input ?? 3000 * turns + Math.round(read / 3);
const outputTokens = transcript.usage?.output ?? 120 * turns;
const result = {
  type: "result", subtype: transcript.stop ?? "success", is_error: !!transcript.stop, num_turns: turns, ...(transcript.stop ? {} : { result: transcript.answer }),
  total_cost_usd: 0, usage: { input_tokens: inputTokens, output_tokens: outputTokens, cache_read_input_tokens: 0, cache_creation_input_tokens: 0 },
  modelUsage: { [model]: { inputTokens, outputTokens, cacheReadInputTokens: 0, cacheCreationInputTokens: 0, costUSD: 0 } },
};
if (transcript.splitUtf8) await emitSplit(result);
else emit(result);
