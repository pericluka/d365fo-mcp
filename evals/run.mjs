#!/usr/bin/env node
// Eval harness for how Claude uses the F&O tools. Every scenario starts the fake Entra and F&O of test/support.mjs,
// runs the Claude Code CLI headless with an MCP config that holds only the local stdio server (a copy of dist/index.js)
// pointed at the fake, then grades the F&O requests that reached the fake and the final answer. Nothing real is
// contacted except the model itself. With --dry-run a scripted stand-in replaces the CLI, which checks the harness and
// the grading without a model. See evals/README.md.
import { spawn } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { parseArgs } from "node:util";
import { copyBuiltServer, makeCert, projectDir, serverEnv, startFakeCloud, stopProcessTree } from "../test/support.mjs";
import { filterRows } from "./odata-filter.mjs";
import { parseRequest, READ_TOOLS, scenarios, WRITE_TOOLS } from "./scenarios.mjs";

const SERVER = "fo"; // the MCP server name in the config, so the tools are mcp__fo__query_entity and so on
const DIST = join(projectDir, "dist");
const FAKE_CLI = join(projectDir, "evals/fake-claude.mjs");
const PACKAGE = JSON.parse(readFileSync(join(projectDir, "package.json"), "utf8"));
/** The User-Agent of the server's F&O requests, which tells the fake's own server apart from any other. */
const SERVER_AGENT = `fo-mcp/${PACKAGE.version}`;
/**
 * Tools besides mcp__fo__ that the CLI may list without making a run unsafe. They read resources of the MCP servers of
 * the session, which the guard limits to the fake's server. --allowedTools does not allow them anyway.
 */
const RESOURCE_TOOLS = ["ListMcpResourcesTool", "ReadMcpResourceTool"];

const USAGE = `Usage: npm run eval -- [options]

  --trials N         runs per scenario, a scenario passes only when every run passes (default 1)
  --scenario NAMES   only these scenarios, comma separated: ${scenarios.map((s) => s.name).join(", ")}
  --model MODEL      model for the CLI, for example sonnet or opus (default: the CLI's default)
  --dry-run          replay scripted transcripts instead of running the CLI, no model and no cost (npm test runs it)
  --token-budget N   most tokens one run may use, input with cache reads plus output, 0 for no limit (default 200000)
  --max-turns N      turns the CLI may take per run (default 15)
  --max-usd N        spending cap the CLI enforces per run (default 1)
  --timeout S        seconds before a run is stopped (default 300)
  --report FILE      write every run with its checks, tool calls, F&O requests and answer as JSON
  --cli PATH         the Claude Code CLI to run (default: claude on PATH)`;

let options;
try {
  ({ values: options } = parseArgs({
    options: {
      trials: { type: "string", default: "1" }, scenario: { type: "string" }, model: { type: "string" }, "dry-run": { type: "boolean", default: false },
      "token-budget": { type: "string", default: "200000" }, "max-turns": { type: "string", default: "15" }, "max-usd": { type: "string", default: "1" },
      timeout: { type: "string", default: "300" }, report: { type: "string" }, cli: { type: "string", default: "claude" }, help: { type: "boolean", default: false },
    },
  }));
} catch (error) {
  console.error(`${error.message}\n\n${USAGE}`);
  process.exit(2);
}
if (options.help) {
  console.log(USAGE);
  process.exit(0);
}
const number = (name, min) => {
  const value = Number(options[name]);
  if (!Number.isFinite(value) || value < min) {
    console.error(`--${name} must be a number of at least ${min}, got '${options[name]}'`);
    process.exit(2);
  }
  return value;
};
const settings = {
  trials: number("trials", 1), tokenBudget: number("token-budget", 0), maxTurns: number("max-turns", 1), maxUsd: number("max-usd", 0.01),
  timeoutMs: number("timeout", 10) * 1000,
};
const wanted = options.scenario?.split(",").map((s) => s.trim()).filter(Boolean);
const unknown = wanted?.filter((name) => !scenarios.some((s) => s.name === name)) ?? [];
if (unknown.length) {
  console.error(`Unknown scenario ${unknown.join(", ")}. Known: ${scenarios.map((s) => s.name).join(", ")}`);
  process.exit(2);
}
const selected = wanted ? scenarios.filter((s) => wanted.includes(s.name)) : scenarios;
if (!existsSync(join(DIST, "index.js"))) {
  console.error("dist/index.js is missing. npm run eval builds it, or run npm run build first.");
  process.exit(2);
}

// ---------------------------------------------------------------- Isolation

const BUILT = readdirSync(DIST).filter((file) => file.endsWith(".js"));

/** Every FO_ variable the built code mentions, in any file. The server fills an unset one from the .env next to it. */
const SERVER_VARIABLES = [...new Set(BUILT.flatMap((file) => readFileSync(join(DIST, file), "utf8").match(/\bFO_[A-Z0-9_]+\b/g) ?? []))];

/**
 * A copy of the built server in the eval's temporary folder, with a package.json of its own and the project's
 * node_modules linked in (see copyBuiltServer). The server loads .env from the folder of its package.json, so the copy
 * never sees the developer's .env, which points at a real F&O, whatever variable a later version reads from it.
 * Returns the script.
 */
function copyServer(work) {
  return join(copyBuiltServer(join(work, "server")), "dist", "index.js");
}

/**
 * Refuse a server environment that could reach anything but the fake. The server copy has no .env next to it. Every
 * variable is set here anyway, so neither a .env nor this process's environment can point it elsewhere.
 */
function assertFakeOnly(env, cloud, script, work) {
  const problems = [];
  if (!script.startsWith(join(work, "server"))) problems.push(`the server runs from ${script}, not from the eval's copy`);
  if (existsSync(join(dirname(dirname(script)), ".env"))) problems.push("the server copy has a .env next to it");
  if (new URL(cloud.origin).hostname !== "localhost") problems.push(`the fake runs at ${cloud.origin}, not on localhost`);
  if (env.FO_URL !== cloud.foUrl) problems.push(`FO_URL is ${env.FO_URL}`);
  if (env.FO_AUTHORITY !== cloud.origin) problems.push(`FO_AUTHORITY is ${env.FO_AUTHORITY}`);
  if (env.FO_HOST_IP) problems.push("FO_HOST_IP is set");
  const unset = SERVER_VARIABLES.filter((name) => env[name] === undefined);
  if (unset.length) problems.push(`serverEnv in test/support.mjs leaves ${unset.join(", ")} unset, so a .env could fill them in`);
  const proxies = ["HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"].filter((name) => env[name] !== "");
  if (proxies.length) problems.push(`${proxies.join(", ")} not blanked`);
  if (problems.length) throw new Error(`Refusing to run, the server could reach more than the fake: ${problems.join("; ")}.`);
}

/** Variables of the CLI's own login that pass through. Every other CLAUDE variable belongs to the session that started the eval. */
const CLI_LOGIN = ["CLAUDE_CONFIG_DIR", "CLAUDE_CODE_OAUTH_TOKEN", "CLAUDE_CODE_USE_BEDROCK", "CLAUDE_CODE_USE_VERTEX", "CLAUDE_CODE_USE_FOUNDRY"];

/**
 * The CLI's environment: this process's without CLAUDECODE and the other variables of a Claude Code session (a CLI
 * started from inside one would act as part of it), without MCP and F&O settings, with CLAUDE.md files and auto
 * memory turned off so the user's notes do not steer the model.
 */
function cliEnv(transcript) {
  const env = {};
  for (const [name, value] of Object.entries(process.env)) {
    if ((/^CLAUDE/.test(name) && !CLI_LOGIN.includes(name)) || /^(MCP_|FO_)/.test(name)) continue;
    env[name] = value;
  }
  Object.assign(env, { CLAUDE_CODE_DISABLE_CLAUDE_MDS: "1", CLAUDE_CODE_DISABLE_AUTO_MEMORY: "1", ENABLE_CLAUDEAI_MCP_SERVERS: "false", DISABLE_AUTOUPDATER: "1" });
  if (transcript) env.EVAL_TRANSCRIPT = JSON.stringify(transcript);
  return env;
}

/** Why the CLI's init message shows more than the fake's server, or undefined when it shows only that. */
function foreignSetup(init) {
  const servers = (init.mcp_servers ?? []).filter((s) => s.name !== SERVER).map((s) => s.name);
  const tools = (init.tools ?? []).filter((t) => !t.startsWith(`mcp__${SERVER}__`) && !RESOURCE_TOOLS.includes(t));
  if (!servers.length && !tools.length) return undefined;
  return `the CLI loaded more than the fake's server: ${[...servers.map((s) => `server ${s}`), ...tools.map((t) => `tool ${t}`)].join(", ")}`;
}

// ---------------------------------------------------------------- Running the CLI

let current; // the CLI process of the run in progress, stopped on Ctrl-C

/**
 * Why the fo server that answered the run's tool calls was not the eval's copy, or undefined when it was. A server of
 * that name from anywhere else would answer without a single request from the copy reaching the fake, since every tool
 * reads F&O metadata or data before it can succeed.
 */
function foreignAnswers(calls, cloud) {
  const answered = calls.filter((c) => c.fo && c.result !== undefined && !c.isError);
  if (!answered.length || cloud.seen.foRequests.some((r) => r.agent === SERVER_AGENT)) return undefined;
  const count = answered.length === 1 ? "1 tool call" : `${answered.length} tool calls`;
  return `${count} of the ${SERVER} server succeeded but no request from ${SERVER_AGENT} reached the fake, so another server answered`;
}

/**
 * Run the CLI and collect its stream-json messages. The init message comes before the first tool call, so a CLI that
 * loaded anything besides the fake's server is stopped before it can call a tool. The first model request may already
 * be on its way by then, but it can only lead to a tool call after the init check.
 */
function runCli([command, ...prefix], args, { cwd, env, timeoutMs }) {
  return new Promise((resolve) => {
    // A process group of its own on macOS and Linux, see stopProcessTree. On Windows detached would only give the CLI a
    // console window of its own.
    const child = spawn(command, [...prefix, ...args], { cwd, env, stdio: ["ignore", "pipe", "pipe"], detached: process.platform !== "win32", windowsHide: true });
    current = child;
    const messages = [];
    let stderr = "";
    let buffer = "";
    let problem;
    let done = false;
    const stop = (kind, message) => {
      problem ??= { kind, message };
      stopProcessTree(child);
      setTimeout(() => stopProcessTree(child, "SIGKILL"), 3000).unref();
    };
    const timer = setTimeout(() => stop("error", `no result within ${timeoutMs / 1000} s`), timeoutMs);
    // A tool result can be 40 KB, so a multibyte character of the answer can fall on a chunk boundary. Decoding each chunk
    // on its own would turn its halves into replacement characters.
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    const finish = (code) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      current = undefined;
      // An MCP server the CLI left behind would keep running against the next scenario's data.
      stopProcessTree(child, "SIGKILL");
      resolve({ messages, stderr, code, problem });
    };
    child.stdout.on("data", (chunk) => {
      buffer += chunk;
      let newline;
      while ((newline = buffer.indexOf("\n")) >= 0) {
        const line = buffer.slice(0, newline).trim();
        buffer = buffer.slice(newline + 1);
        if (!line) continue;
        let message;
        try {
          message = JSON.parse(line);
        } catch {
          stderr += `${line}\n`;
          continue;
        }
        const initSeen = messages.some((m) => m.type === "system" && m.subtype === "init");
        messages.push(message);
        if (message.type === "system" && message.subtype === "init") {
          const foreign = foreignSetup(message);
          const status = message.mcp_servers?.find((s) => s.name === SERVER)?.status;
          if (foreign) stop("unsafe", foreign);
          else if (status !== "connected") stop("error", `the ${SERVER} MCP server did not connect (${status ?? "not listed"})`);
        } else if (!initSeen && message.type === "assistant") {
          stop("unsafe", "the CLI answered before it reported its tools and MCP servers");
        }
      }
    });
    child.stderr.on("data", (d) => (stderr += d));
    child.on("error", (error) => {
      problem ??= { kind: "error", message: `could not start ${command}: ${error.message}` };
      finish(null);
    });
    child.on("close", finish);
  });
}

/** The tool calls of a session with their results, in order. */
function toolCalls(messages) {
  const calls = [];
  const byId = new Map();
  const blocks = (content) => (Array.isArray(content) ? content : []);
  const text = (content) => (typeof content === "string" ? content : blocks(content).map((b) => b.text ?? "").join("\n"));
  for (const m of messages) {
    if (m.type === "assistant") {
      for (const block of blocks(m.message?.content).filter((b) => b.type === "tool_use")) {
        const fo = block.name.startsWith(`mcp__${SERVER}__`);
        const call = { tool: fo ? block.name.slice(`mcp__${SERVER}__`.length) : block.name, fo, input: block.input };
        calls.push(call);
        byId.set(block.id, call);
      }
    } else if (m.type === "user") {
      for (const block of blocks(m.message?.content).filter((b) => b.type === "tool_result")) {
        const call = byId.get(block.tool_use_id);
        if (call) Object.assign(call, { isError: !!block.is_error, result: text(block.content) });
      }
    }
  }
  return calls;
}

/**
 * The size of the tool results of a session, in all and per tool. The model reads them again on every later turn, so
 * they are where the tokens of a run go: a describe_entity without fields on a wide entity is 20 KB on its own.
 */
function resultsOf(calls) {
  const byTool = {};
  for (const c of calls) byTool[c.tool] = (byTool[c.tool] ?? 0) + (c.result?.length ?? 0);
  return { chars: Object.values(byTool).reduce((total, n) => total + n, 0), byTool };
}

/** Tokens and cost of a session: input counts cache reads and writes too, that is what the model had to take in. */
function usageOf(result) {
  const models = Object.values(result?.modelUsage ?? {});
  const sum = (key) => models.reduce((total, m) => total + (m[key] ?? 0), 0);
  const u = result?.usage ?? {};
  const input = models.length
    ? sum("inputTokens") + sum("cacheReadInputTokens") + sum("cacheCreationInputTokens")
    : (u.input_tokens ?? 0) + (u.cache_read_input_tokens ?? 0) + (u.cache_creation_input_tokens ?? 0);
  const output = models.length ? sum("outputTokens") : (u.output_tokens ?? 0);
  return { input, output, total: input + output, cost: result?.total_cost_usd ?? 0 };
}

/** One run of a scenario: seed the fake, run the CLI (or the stand-in with a transcript) and grade the outcome. */
async function runOnce(scenario, { cloud, certFile, work, script }, transcript) {
  cloud.reset();
  cloud.faults.filterRows = filterRows;
  cloud.faults.readBy = false; // a field real F&O does not have, which the model would see in every customer read
  const restore = scenario.setup?.(cloud);
  try {
    const env = serverEnv(cloud, certFile, { FO_COMPANY: "USMF", FO_ALLOW_WRITES: scenario.writes ? "1" : "0", ...scenario.env });
    assertFakeOnly(env, cloud, script, work);
    const offered = [...READ_TOOLS, ...(scenario.writes ? WRITE_TOOLS : [])];
    const allowed = scenario.tools ?? offered;
    const name = (tool) => `mcp__${SERVER}__${tool}`;
    const config = join(work, "mcp.json");
    writeFileSync(config, JSON.stringify({ mcpServers: { [SERVER]: { type: "stdio", command: process.execPath, args: [script], env } } }), { mode: 0o600 });
    const disallowed = offered.filter((t) => !allowed.includes(t));
    const args = [
      "-p", scenario.prompt, "--output-format", "stream-json", "--verbose",
      // Only the fake's server: no built-in tools, no settings files (hooks, plugins, permission rules), no skills or slash commands.
      "--strict-mcp-config", "--mcp-config", config, "--tools", "", "--setting-sources", "", "--disable-slash-commands",
      "--allowedTools", allowed.map(name).join(","), ...(disallowed.length ? ["--disallowedTools", disallowed.map(name).join(",")] : []),
      "--permission-mode", "dontAsk", "--no-session-persistence", "--max-turns", String(settings.maxTurns), "--max-budget-usd", String(settings.maxUsd),
      ...(options.model ? ["--model", options.model] : []),
    ];
    const cli = transcript ? [process.execPath, FAKE_CLI] : [options.cli];
    const session = await runCli(cli, args, { cwd: join(work, "session"), env: cliEnv(transcript), timeoutMs: settings.timeoutMs });
    return grade(scenario, session, cloud);
  } finally {
    restore?.();
  }
}

/**
 * Turn a finished session into a run with its checks and status: pass, fail, inconclusive (only a precondition such as
 * reading the planted text failed), error (the harness, the CLI or the model's API broke, or the CLI stopped before
 * its final answer) or unsafe (the CLI loaded more than the fake's server, or another server answered its calls).
 */
function grade(scenario, session, cloud) {
  const { messages, stderr, problem } = session;
  const init = messages.find((m) => m.type === "system" && m.subtype === "init");
  const result = messages.findLast((m) => m.type === "result");
  const calls = toolCalls(messages);
  const requests = cloud.seen.foRequests.map(parseRequest);
  const usage = usageOf(result);
  const run = {
    scenario: scenario.name, status: "pass", checks: [], answer: typeof result?.result === "string" ? result.result : "", turns: result?.num_turns ?? 0, usage,
    results: resultsOf(calls),
    ...(result && result.subtype !== "success" ? { stopped: result.subtype } : {}),
    // What the CLI reported it loaded, the record that the run saw nothing but the fake.
    loaded: { model: init?.model, servers: init?.mcp_servers?.map((s) => `${s.name} ${s.status}`), tools: init?.tools },
    calls,
    requests: requests.map((r) => ({ method: r.method, path: r.path, ...(r.body !== undefined ? { body: r.body } : {}) })),
  };
  if (problem) return { ...run, status: problem.kind === "unsafe" ? "unsafe" : "error", error: problem.message, stderr: stderr.slice(-2000) };
  const foreign = foreignAnswers(calls, cloud);
  if (foreign) return { ...run, status: "unsafe", error: foreign };
  if (!result) return { ...run, status: "error", error: `the CLI ended without a result (exit code ${session.code})`, stderr: stderr.slice(-2000) };
  if (result.is_error && result.subtype === "success") {
    // An API error such as a failed login comes as a result with is_error and the message as text.
    const login = /authenticat|oauth|api key|\/login|log ?in/i.test(run.answer);
    return { ...run, status: "error", error: run.answer || "the CLI reported an error", ...(login ? { login: true } : {}) };
  }
  const checks = scenario.grade({ answer: run.answer, calls, requests, tables: cloud.tables });
  if (settings.tokenBudget) {
    checks.push({ name: "token budget", ok: usage.total <= settings.tokenBudget, detail: `${thousands(usage.total)} tokens, budget ${thousands(settings.tokenBudget)}` });
  }
  if (result.subtype !== "success") {
    // Cut off by --max-turns or --max-usd: the checks that pass say nothing about the turns that never ran, a write among them.
    return { ...run, status: "error", error: `the CLI stopped with ${result.subtype} before its final answer`, checks };
  }
  const failed = checks.filter((c) => !c.ok);
  const status = !failed.length ? "pass" : failed.every((c) => c.inconclusive) ? "inconclusive" : "fail";
  return { ...run, status, checks };
}

// ---------------------------------------------------------------- Output

const thousands = (n) => (n >= 1000 ? `${(n / 1000).toFixed(1)}k` : String(Math.round(n)));
const kilobytes = (chars) => `${(chars / 1000).toFixed(1)} KB`;
const average = (runs, pick) => runs.reduce((total, r) => total + pick(r), 0) / Math.max(runs.length, 1);

function table(rows) {
  const widths = rows[0].map((_, i) => Math.max(...rows.map((r) => String(r[i]).length)));
  return rows.map((r) => r.map((cell, i) => String(cell).padEnd(widths[i])).join("  ").trimEnd()).join("\n");
}

const firstProblem = (run) => (run.error ?? run.checks.find((c) => !c.ok)?.name ?? "").slice(0, 80);

/** What a reader needs to see why a run did not pass: the failed checks, the tool calls and the answer. */
function explainRun(run, trial) {
  const lines = [`${run.scenario} #${trial} ${run.status.toUpperCase()}${run.stopped ? ` (stopped: ${run.stopped})` : ""}`];
  if (run.error) lines.push(`  ${run.error}`);
  for (const c of run.checks.filter((c) => !c.ok)) lines.push(`  ${c.name}: ${c.detail ?? "failed"}`);
  for (const c of run.calls) {
    const outcome = c.isError ? `error: ${(c.result ?? "").slice(0, 160)}` : "ok";
    lines.push(`  call ${c.tool} ${JSON.stringify(c.input).slice(0, 200)} -> ${outcome}`);
  }
  if (run.answer && run.answer !== run.error) lines.push(`  answer: ${run.answer.replace(/\s+/g, " ").slice(0, 400)}`);
  if (run.stderr && run.status !== "pass") lines.push(`  stderr: ${run.stderr.trim().split("\n").slice(-5).join(" | ")}`);
  return lines.join("\n");
}

// ---------------------------------------------------------------- Modes

async function evaluate(context) {
  const runs = [];
  let halt;
  outer: for (const scenario of selected) {
    for (let trial = 1; trial <= settings.trials; trial++) {
      const run = { ...(await runOnce(scenario, context)), trial };
      runs.push(run);
      const cost = `$${run.usage.cost.toFixed(2)}`;
      // describe_entity is named next to the total, it is the result that grows with the width of an entity.
      const described = run.results.byTool.describe_entity;
      const results = `${kilobytes(run.results.chars)} of tool results${described ? ` (${kilobytes(described)} from describe_entity)` : ""}`;
      console.error(`${scenario.name} #${trial}: ${run.status}, ${run.turns} turns, ${run.calls.length} calls, ${thousands(run.usage.total)} tokens, ${results}, ${cost}`);
      if (run.status === "unsafe") halt = `Stopped: ${run.error}. No further runs.`;
      else if (run.login) halt = `Stopped: the Claude CLI could not sign in (${run.error}). Run claude once to sign in, or set ANTHROPIC_API_KEY.`;
      if (halt) break outer;
    }
  }
  const rows = [["scenario", "result", "passed", "turns", "calls", "tool results", "input", "output", "cost", "first problem"]];
  for (const scenario of selected) {
    const mine = runs.filter((r) => r.scenario === scenario.name);
    if (!mine.length) continue;
    const passed = mine.filter((r) => r.status === "pass").length;
    const inconclusive = mine.length === settings.trials && mine.every((r) => r.status === "pass" || r.status === "inconclusive");
    rows.push([
      scenario.name, passed === settings.trials ? "PASS" : inconclusive ? "INCONCLUSIVE" : "FAIL", `${passed}/${settings.trials}`, average(mine, (r) => r.turns).toFixed(1),
      average(mine, (r) => r.calls.length).toFixed(1), kilobytes(average(mine, (r) => r.results.chars)),
      thousands(average(mine, (r) => r.usage.input)), thousands(average(mine, (r) => r.usage.output)),
      `$${mine.reduce((total, r) => total + r.usage.cost, 0).toFixed(2)}`, firstProblem(mine.find((r) => r.status !== "pass") ?? { checks: [] }),
    ]);
  }
  console.log(table(rows));
  const budgeted = runs.map((r) => r.checks.find((c) => c.name === "token budget")).filter(Boolean);
  if (budgeted.length) {
    console.log(`token budget ${thousands(settings.tokenBudget)} per run: ${budgeted.filter((c) => c.ok).length} of ${budgeted.length} graded runs within it`);
  }
  console.log(`total cost $${runs.reduce((total, r) => total + r.usage.cost, 0).toFixed(2)} as reported by the CLI${options.model ? `, model ${options.model}` : ""}`);
  const failed = runs.filter((r) => r.status !== "pass");
  if (failed.length) console.log(`\n${failed.map((r) => explainRun(r, r.trial)).join("\n\n")}`);
  if (halt) console.log(`\n${halt}`);
  if (options.report) writeFileSync(options.report, `${JSON.stringify({ settings, model: options.model ?? null, runs }, null, 2)}\n`);
  const incomplete = selected.some((s) => runs.filter((r) => r.scenario === s.name).length < settings.trials);
  return halt ? 2 : failed.length || incomplete ? 1 : 0;
}

/**
 * The self-check, which npm test runs: every scripted transcript of every scenario must end with the status it
 * expects. One expected to fail or be inconclusive must do so on the check it names. More cases cover the harness
 * itself: the token budget, the guard against a CLI that loaded more than the fake or whose fo server is not the
 * eval's copy, a run cut off by --max-turns, the CLI's resource tools and an answer split inside a UTF-8 character.
 */
async function dryRun(context) {
  const cases = selected.flatMap((s) => {
    const kinds = new Set(s.dry.map((c) => c.expect));
    if (!kinds.has("pass") || !kinds.has("fail")) throw new Error(`scenario ${s.name} needs a dry run transcript that passes and one that fails`);
    return s.dry.map(({ name, expect, failed, ...transcript }) => ({ name: `${s.name}/${name ?? expect}`, scenario: s, transcript, expect, failed }));
  });
  const names = cases.map((c) => c.name);
  const twice = names.filter((name, i) => names.indexOf(name) !== i);
  if (twice.length) throw new Error(`dry run cases need distinct names, ${[...new Set(twice)].join(", ")} come more than once`);
  const [first] = selected;
  const passing = (scenario) => {
    const { name, expect, failed, ...transcript } = scenario.dry.find((c) => c.expect === "pass");
    return transcript;
  };
  if (settings.tokenBudget) {
    const usage = { input: settings.tokenBudget, output: 1000 };
    cases.push({ name: "token-budget/fail", scenario: first, transcript: { ...passing(first), usage }, expect: "fail", failed: "token budget" });
  }
  // The stand-in claims a second MCP server and Bash, then waits before its calls: the harness must stop it first.
  const unsafe = { ...passing(first), extraServers: ["fo-mcp"], extraTools: ["Bash", "mcp__fo-mcp__update_record"], pauseMs: 10_000 };
  cases.push({ name: "guard/unsafe", scenario: first, transcript: unsafe, expect: "unsafe", noRequests: true });
  // A server named fo that is not the eval's copy: the stand-in answers the calls itself and nothing reaches the fake.
  cases.push({ name: "guard/elsewhere", scenario: first, transcript: { ...passing(first), forgeResults: true }, expect: "unsafe" });
  cases.push({ name: "guard/resource-tools", scenario: first, transcript: { ...passing(first), extraTools: RESOURCE_TOOLS }, expect: "pass" });
  cases.push({ name: "harness/max-turns", scenario: first, transcript: { ...passing(first), stop: "error_max_turns" }, expect: "error" });
  const apostrophe = selected.find((s) => s.name === "invented-field");
  if (apostrophe) cases.push({ name: "harness/split-utf8", scenario: apostrophe, transcript: { ...passing(apostrophe), splitUtf8: true }, expect: "pass" });

  const rows = [["case", "expected", "got", "ok", "detail"]];
  const wrong = [];
  const report = [];
  for (const c of cases) {
    const run = await runOnce(c.scenario, context, c.transcript);
    const failedAsNamed = !c.failed || run.checks.some((check) => check.name === c.failed && !check.ok);
    const quiet = !c.noRequests || run.requests.every((r) => !r.path.startsWith("/data/"));
    // The fake must show the model nothing real F&O would not, such as the ReadBy field the tests use.
    const faithful = run.calls.every((call) => !call.result?.includes('"ReadBy"'));
    const ok = run.status === c.expect && failedAsNamed && quiet && faithful;
    if (!ok) wrong.push(`${explainRun(run, 1)}${faithful ? "" : "\n  a tool result showed ReadBy, which the fake adds only for the tests"}`);
    const detail = run.error ?? (c.failed ? run.checks.find((check) => check.name === c.failed && !check.ok)?.detail : "") ?? "";
    rows.push([c.name, c.expect, run.status, ok ? "ok" : "WRONG", detail.replace(/\s+/g, " ").slice(0, 90)]);
    report.push({ name: c.name, expected: c.expect, got: run.status, ok, ...(c.failed ? { failed: c.failed } : {}), run });
  }
  console.log(table(rows));
  if (wrong.length) console.log(`\n${wrong.join("\n\n")}`);
  console.log(`\ndry run: ${cases.length - wrong.length} of ${cases.length} cases graded as expected`);
  if (options.report) {
    const isolation = { scanned: BUILT, variables: SERVER_VARIABLES, server: context.script };
    writeFileSync(options.report, `${JSON.stringify({ dryRun: true, settings, isolation, cases: report }, null, 2)}\n`);
  }
  return wrong.length ? 1 : 0;
}

// ---------------------------------------------------------------- Main

const cert = makeCert();
const cloud = await startFakeCloud(cert.dir);
const work = mkdtempSync(join(tmpdir(), "fo-mcp-eval-"));
mkdirSync(join(work, "session"));
const cleanUp = async () => {
  await cloud.close();
  cert.remove();
  rmSync(work, { recursive: true, force: true });
};
process.on("SIGINT", async () => {
  if (current) stopProcessTree(current, "SIGKILL");
  await cleanUp();
  process.exit(130);
});

let code;
try {
  const context = { cloud, certFile: cert.certFile, work, script: copyServer(work) };
  code = options["dry-run"] ? await dryRun(context) : await evaluate(context);
} catch (error) {
  console.error(`eval: ${error.message}`);
  code = 2;
} finally {
  await cleanUp();
}
process.exit(code);
