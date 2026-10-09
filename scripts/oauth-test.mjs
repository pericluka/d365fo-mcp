#!/usr/bin/env node
// End to end test of the remote server the way an MCP client does it: discover the OAuth front, register,
// send the user to sign in, receive the callback on localhost, trade the code for tokens and call a tool.
// Usage: node scripts/oauth-test.mjs [server url] [tool] ['<json args>']
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { UnauthorizedError } from "@modelcontextprotocol/sdk/client/auth.js";
import { execFile } from "node:child_process";
import { randomBytes } from "node:crypto";
import { createServer } from "node:http";

const [serverUrl = "http://localhost:3000/mcp", tool = "environment_info", rawArgs] = process.argv.slice(2);
const callbackPort = 8787;
// The loopback address rather than localhost, so the browser comes back to the listener below and to nothing else.
const redirectUrl = `http://127.0.0.1:${callbackPort}/callback`;
// A callback that does not bring this value back was not started by this run and is ignored.
const state = randomBytes(16).toString("base64url");

/** Minimal in-memory OAuthClientProvider, the part every MCP client implements. */
const provider = {
  redirectUrl,
  clientMetadata: { client_name: "fo-mcp oauth test", redirect_uris: [redirectUrl], grant_types: ["authorization_code", "refresh_token"], response_types: ["code"], token_endpoint_auth_method: "none" },
  _client: undefined,
  _tokens: undefined,
  _verifier: undefined,
  clientInformation() { return this._client; },
  saveClientInformation(info) { this._client = info; },
  tokens() { return this._tokens; },
  saveTokens(tokens) { this._tokens = tokens; },
  codeVerifier() { return this._verifier; },
  saveCodeVerifier(v) { this._verifier = v; },
  state() { return state; },
  redirectToAuthorization(url) {
    const href = String(url);
    console.error(`Sign in here:\n${href}\n`);
    // The script registers a new client on every run, so the server asks for approval every time.
    console.error("The browser shows the server's consent page for this test client first. Approve it, then sign in with Microsoft.\n");
    // The URL comes from the server, so it never goes through a shell. When no browser opens, paste the URL above.
    if (url.protocol !== "https:" && url.protocol !== "http:") return;
    const [command, args] =
      process.platform === "win32" ? ["rundll32", ["url.dll,FileProtocolHandler", href]] : process.platform === "darwin" ? ["open", [href]] : ["xdg-open", [href]];
    execFile(command, args, () => {});
  },
};

/**
 * Listen for the browser coming back with the code. It listens before the sign in starts, so a browser that is
 * signed in already and comes straight back cannot miss it. Returns the code as a promise and a way to stop listening.
 */
function listenForCallback() {
  let settle;
  const code = new Promise((resolve, reject) => (settle = { resolve, reject }));
  // Awaited only after a sign in, a failure must not count as unhandled before that.
  code.catch(() => {});
  const server = createServer((req, res) => {
    const u = new URL(req.url, redirectUrl);
    // Plain text: the query comes from whoever opened this URL, none of it may be read as markup.
    res.setHeader("content-type", "text/plain; charset=utf-8");
    res.setHeader("x-content-type-options", "nosniff");
    // A kept alive browser connection would hold the process open after the sign in.
    res.setHeader("connection", "close");
    if (u.pathname !== "/callback") { res.statusCode = 404; res.end(); return; }
    if (u.searchParams.get("state") !== state) {
      res.statusCode = 400;
      res.end("This sign in was not started by this run of oauth-test.mjs. Close this tab.");
      return;
    }
    const received = u.searchParams.get("code");
    const error = u.searchParams.get("error") ?? "no code";
    const description = u.searchParams.get("error_description") ?? "";
    res.end(received ? "Signed in. You can close this tab." : `Sign in failed: ${error} ${description}`);
    server.close();
    received ? settle.resolve(received) : settle.reject(new Error(`${error}: ${description}`));
  });
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(callbackPort, "127.0.0.1", () => resolve({ code, close: () => server.close() }));
  });
}

const client = new Client({ name: "fo-mcp-oauth-test", version: "0.1.0" });
let transport = new StreamableHTTPClientTransport(new URL(serverUrl), { authProvider: provider });
let callback;
try {
  callback = await listenForCallback();
  try {
    await client.connect(transport);
  } catch (error) {
    if (!(error instanceof UnauthorizedError)) throw error;
    await transport.finishAuth(await callback.code);
    transport = new StreamableHTTPClientTransport(new URL(serverUrl), { authProvider: provider });
    await client.connect(transport);
  }
  console.error("Connected, access token issued by the server:", provider._tokens?.access_token?.slice(0, 12) + "...");
  const result = await client.callTool({ name: tool, arguments: rawArgs ? JSON.parse(rawArgs) : {} }, undefined, { timeout: 120_000 });
  for (const c of result.content) console.log(c.type === "text" ? c.text : JSON.stringify(c));
  if (result.isError) process.exitCode = 1;
} catch (error) {
  console.error(error.code === "EADDRINUSE" ? `Port ${callbackPort} is in use, the sign in needs it for the callback.` : error.message);
  process.exitCode = 1;
} finally {
  callback?.close();
  await client.close().catch(() => {});
}
