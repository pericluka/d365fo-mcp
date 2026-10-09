#!/usr/bin/env node
// Usage: node scripts/call.mjs <tool> '<json args>'   (no arguments lists the tools with their arguments)
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { fileURLToPath } from "node:url";

const [tool, rawArgs] = process.argv.slice(2);
const server = fileURLToPath(new URL("../dist/index.js", import.meta.url));
const client = new Client({ name: "fo-mcp-cli", version: "0.1.0" });

try {
  const args = rawArgs ? JSON.parse(rawArgs) : {};
  // Pass the full environment through, so FO_* variables set on the command line override .env. Audit lines belong in a
  // server log, here they would mix with the answer, so they are off unless FO_AUDIT=1 is set on the command line.
  const env = { ...process.env, FO_AUDIT: process.env.FO_AUDIT?.trim() || "0" };
  await client.connect(new StdioClientTransport({ command: "node", args: [server], env, stderr: "inherit" }));
  if (!tool) {
    // The tools refuse arguments they do not know, so the list shows the valid names.
    const { tools } = await client.listTools();
    for (const t of tools) console.log(`${t.name}(${Object.keys(t.inputSchema?.properties ?? {}).join(", ")}): ${t.description}\n`);
  } else {
    // Allow more than the SDK default of 60 s, the first call after an environment start can be slow.
    const result = await client.callTool({ name: tool, arguments: args }, undefined, { timeout: 120_000 });
    for (const c of result.content) console.log(c.type === "text" ? c.text : JSON.stringify(c));
    if (result.isError) process.exitCode = 1;
  }
} catch (error) {
  console.error(error instanceof SyntaxError ? `The arguments are not valid JSON: ${error.message}` : error.message);
  process.exitCode = 1;
} finally {
  await client.close().catch(() => {});
}
