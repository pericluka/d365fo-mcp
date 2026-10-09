#!/usr/bin/env node
// End to end test of the remote server without an MCP client:
// 1. sign in a user with the device code flow and get a token for the server's API scope
// 2. call the server over Streamable HTTP with that token and run a tool
// Usage: node scripts/login-test.mjs [server url] [tool] ['<json args>']
// The device code flow needs an app registration that allows public client flows. Use a separate test app for it, set
// LOGIN_TEST_CLIENT_ID to its client ID and add that ID to MCP_ALLOWED_CLIENT_APPS of the server, see README. Without it
// the script signs in as FO_CLIENT_ID, whose tokens a server off localhost accepts only when MCP_ALLOWED_CLIENT_APPS lists it.
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { parseEnv } from "node:util";
import { fileURLToPath } from "node:url";

const projectDir = fileURLToPath(new URL("..", import.meta.url));
const envFile = `${projectDir}/.env`;
if (existsSync(envFile)) {
  for (const [k, v] of Object.entries(parseEnv(readFileSync(envFile, "utf8").replace(/^﻿/, "")))) process.env[k] ??= v;
}

const [serverUrl = `http://localhost:${process.env.MCP_PORT || 3000}/mcp`, tool = "environment_info", rawArgs] = process.argv.slice(2);
const authority = (process.env.FO_AUTHORITY?.trim() || "https://login.microsoftonline.com").replace(/\/+$/, "");
const tenant = process.env.FO_TENANT_ID?.trim();
const serverApp = process.env.FO_CLIENT_ID?.trim();
const testApp = process.env.LOGIN_TEST_CLIENT_ID?.trim();
if (!tenant || !serverApp) {
  console.error("Set FO_TENANT_ID and FO_CLIENT_ID in .env or in the environment.");
  process.exit(1);
}
if (!testApp) {
  // Public client flows on the server's own app let any program sign users in as that app without its secret, device code phishing included.
  // The server accepts such tokens by default only on localhost. Saying so here explains the refusal a hosted server answers with.
  console.error(
    "LOGIN_TEST_CLIENT_ID is not set, so the sign in uses FO_CLIENT_ID, which then needs Allow public client flows. " +
      "A server off localhost accepts its tokens only when MCP_ALLOWED_CLIENT_APPS lists FO_CLIENT_ID, which a public server should never do. " +
      "Register a separate public test app instead, list it in MCP_ALLOWED_CLIENT_APPS and keep public client flows off on the server's app.\n"
  );
}
const clientId = testApp || serverApp;
// The token is always for the server's API: the audience is api://<FO_CLIENT_ID> unless MCP_AUDIENCE names another Application ID URI.
const audience = process.env.MCP_AUDIENCE?.trim() || `api://${serverApp}`;
const scope = process.env.MCP_SCOPE?.trim() || `${audience}/access_as_user`;
const cacheFile = `${projectDir}/.login-test-token.json`;

async function deviceCodeToken() {
  if (existsSync(cacheFile)) {
    const cached = JSON.parse(readFileSync(cacheFile, "utf8"));
    // A token is reused only for the same tenant, app and scope, so switching to the test app signs in again.
    const same = cached.scope === scope && cached.clientId === clientId && cached.tenant === tenant && cached.authority === authority;
    if (same && cached.expiresAt > Date.now() + 60_000) return cached.accessToken;
  }
  const start = await fetch(`${authority}/${tenant}/oauth2/v2.0/devicecode`, {
    method: "POST",
    body: new URLSearchParams({ client_id: clientId, scope: `${scope} openid profile` }),
  });
  const device = await start.json();
  if (!device.device_code) throw new Error(`Device code request failed: ${JSON.stringify(device)}`);
  console.error(device.message);
  for (;;) {
    await new Promise((r) => setTimeout(r, (device.interval || 5) * 1000));
    const poll = await fetch(`${authority}/${tenant}/oauth2/v2.0/token`, {
      method: "POST",
      body: new URLSearchParams({ grant_type: "urn:ietf:params:oauth:grant-type:device_code", client_id: clientId, device_code: device.device_code }),
    });
    const token = await poll.json();
    if (token.access_token) {
      const cached = { accessToken: token.access_token, expiresAt: Date.now() + token.expires_in * 1000, scope, clientId, tenant, authority };
      writeFileSync(cacheFile, JSON.stringify(cached), { mode: 0o600 });
      return token.access_token;
    }
    if (token.error !== "authorization_pending" && token.error !== "slow_down") throw new Error(`Sign in failed: ${token.error} ${token.error_description}`);
  }
}

const client = new Client({ name: "fo-mcp-login-test", version: "0.1.0" });
try {
  const accessToken = await deviceCodeToken();
  const transport = new StreamableHTTPClientTransport(new URL(serverUrl), { requestInit: { headers: { Authorization: `Bearer ${accessToken}` } } });
  await client.connect(transport);
  const result = await client.callTool({ name: tool, arguments: rawArgs ? JSON.parse(rawArgs) : {} }, undefined, { timeout: 120_000 });
  for (const c of result.content) console.log(c.type === "text" ? c.text : JSON.stringify(c));
  if (result.isError) process.exitCode = 1;
} catch (error) {
  console.error(error.message);
  process.exitCode = 1;
} finally {
  await client.close().catch(() => {});
}
