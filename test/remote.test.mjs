// End to end test of the remote server with nothing real behind it: a fake Entra and a fake F&O (test/support.mjs)
// run in this process over HTTPS with a certificate made for the test, dist/http.js runs as a child process against
// them and the MCP SDK client signs in the way Claude does. Run with npm test.
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { UnauthorizedError } from "@modelcontextprotocol/sdk/client/auth.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import assert from "node:assert/strict";
import { after, before, describe, it } from "node:test";
import {
  assertPage, authorizeInBrowser, callTool, callToolRaw, clientId, clientRedirect, connectWithSignIn, INITIALIZE, makeBrowser, makeCert,
  makeProvider, mcpPost, NO_OPENSSL, random, refreshAt, registerClient, s256, startFakeCloud, startServer, SUITE_TIMEOUT,
} from "./support.mjs";

const WRITE_TOOLS = ["create_record", "update_record"];
const READ_TOOLS = ["describe_entity", "environment_info", "query_entity", "search_entities"];

/** The first JSON-RPC message of an answer, which the transport sends as an SSE stream or as plain JSON. */
async function rpcBody(response) {
  const text = await response.text();
  if ((response.headers.get("content-type") ?? "").includes("text/event-stream")) return JSON.parse(text.split("\n").find((l) => l.startsWith("data: ")).slice(6));
  return text ? JSON.parse(text) : undefined;
}

/** Open a session with a token and return the names of the tools it offers, and the session ID. */
async function toolsOf(url, token) {
  const init = await mcpPost(url, token, INITIALIZE);
  await init.text();
  assert.equal(init.status, 200);
  const session = init.headers.get("mcp-session-id");
  const list = await mcpPost(url, token, { jsonrpc: "2.0", id: 2, method: "tools/list" }, session);
  assert.equal(list.status, 200);
  return { session, tools: (await rpcBody(list)).result.tools.map((t) => t.name).sort() };
}

describe("remote server with Entra sign in", { timeout: SUITE_TIMEOUT, skip: NO_OPENSSL }, () => {
  let cert, cloud, server, serverUrl, port;

  before(async () => {
    cert = makeCert();
    cloud = await startFakeCloud(cert.dir);
    server = await startServer({ cloud, certFile: cert.certFile });
    ({ port } = server);
    serverUrl = server.url;
  });

  after(async () => {
    await server?.stop();
    await cloud?.close();
    cert?.remove();
  });

  it("publishes protected resource metadata that points at its own OAuth front", async () => {
    for (const path of ["/.well-known/oauth-protected-resource/mcp", "/.well-known/oauth-protected-resource"]) {
      const metadata = await (await fetch(`http://localhost:${port}${path}`)).json();
      assert.equal(metadata.resource, serverUrl);
      assert.deepEqual(metadata.authorization_servers, [`http://localhost:${port}`]);
    }
    const as = await (await fetch(`http://localhost:${port}/.well-known/oauth-authorization-server`)).json();
    assert.equal(as.registration_endpoint, `http://localhost:${port}/register`);
    assert.deepEqual(as.code_challenge_methods_supported, ["S256"]);
  });

  it("answers 401 with the metadata URL when there is no token or a bad one", async () => {
    for (const headers of [{}, { authorization: "Bearer not-a-token" }]) {
      const r = await fetch(serverUrl, { method: "POST", headers: { "content-type": "application/json", ...headers }, body: "{}" });
      assert.equal(r.status, 401);
      assert.match(r.headers.get("www-authenticate"), /resource_metadata="http:\/\/localhost:\d+\/.well-known\/oauth-protected-resource\/mcp"/);
    }
  });

  it("refuses to register a redirect URI outside localhost and claude.ai", async () => {
    const r = await fetch(`http://localhost:${port}/register`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ redirect_uris: ["https://evil.example/callback"] }) });
    assert.equal(r.status, 400);
    assert.equal((await r.json()).error, "invalid_redirect_uri");
  });

  it("signs a user in through Entra and runs tools as that user", async () => {
    const provider = makeProvider(cloud, "alice");
    const client = await connectWithSignIn(serverUrl, provider);
    try {
      assert.ok(provider._tokens?.access_token, "the client holds a token from the server");
      assert.ok(provider._tokens.refresh_token, "and a refresh token");
      assert.doesNotMatch(provider._tokens.access_token, /^ey/, "the client must get an opaque token, never the Entra token");

      const info = await callTool(client, "environment_info");
      assert.equal(info.user, "alice@example.com");
      assert.equal(info.applicationVersion, "10.0.48");
      assert.ok(info.legalEntities.some((e) => e.id === "USMF"));

      const rows = await callTool(client, "query_entity", { entity: "CustomersV3", select: "CustomerAccount,OrganizationName" });
      assert.equal(rows.rows[0].ReadBy, "alice@example.com", "F&O must see a token for the signed in user");
      assert.deepEqual([...new Set(cloud.seen.oboScopes)], [`${cloud.foUrl}/.default`]);
    } finally {
      await client.close();
    }
  });

  it("signs users in with MCP_SCOPE and takes direct tokens for MCP_AUDIENCE, for an app registration that exposes its API under another name", async () => {
    const audience = "api://fo-mcp.example.com";
    const scope = `${audience}/read_fo`;
    cloud.identifierUris.add(audience);
    const named = await startServer({ cloud, certFile: cert.certFile, env: { MCP_AUDIENCE: audience, MCP_SCOPE: scope } });
    try {
      assert.match(named.log(), /users sign in with api:\/\/fo-mcp\.example\.com\/read_fo,/);
      const metadata = await (await fetch(`http://localhost:${named.port}/.well-known/oauth-protected-resource/mcp`)).json();
      assert.deepEqual(metadata.scopes_supported, [scope]);

      // Through the server's own sign in: it asks Entra for the scope's name on its own app, and the user's token carries that name.
      const client = await connectWithSignIn(named.url, makeProvider(cloud, "alice"));
      try {
        assert.equal((await callTool(client, "environment_info")).user, "alice@example.com");
        const askedFor = cloud.seen.authorizeRequests.at(-1).scope.split(" ").filter((s) => s.startsWith(clientId));
        assert.deepEqual(askedFor, [`${clientId}/read_fo`]);
      } finally {
        await client.close();
      }

      // Straight from Entra: a token for the audience with the scope's name opens a session, the defaults do not.
      const direct = (overrides, aud = audience) => cloud.userToken("alice", aud, overrides);
      const accepted = await mcpPost(named.url, await direct({ scp: "read_fo" }), INITIALIZE);
      await accepted.text();
      assert.equal(accepted.status, 200);
      const defaultScope = await mcpPost(named.url, await direct({}), INITIALIZE);
      assert.equal(defaultScope.status, 401);
      assert.equal((await defaultScope.json()).error_description, "Token has no read_fo scope of a signed in user");
      const defaultAudience = await mcpPost(named.url, await direct({ scp: "read_fo" }, `api://${clientId}`), INITIALIZE);
      await defaultAudience.text();
      assert.equal(defaultAudience.status, 401);
    } finally {
      cloud.identifierUris.delete(audience);
      await named.stop();
    }
  });

  it("keeps users apart: a second user gets their own F&O token", async () => {
    const client = await connectWithSignIn(serverUrl, makeProvider(cloud, "bob"));
    try {
      const rows = await callTool(client, "query_entity", { entity: "CustomersV3", select: "OrganizationName" });
      assert.equal(rows.rows[0].ReadBy, "bob@example.com");
    } finally {
      await client.close();
    }
  });

  it("names a personal Microsoft account by its email, not its display name", async () => {
    const client = await connectWithSignIn(serverUrl, makeProvider(cloud, "carol"));
    try {
      const info = await callTool(client, "environment_info");
      assert.equal(info.user, "carol@outlook.com");
      const rows = await callTool(client, "query_entity", { entity: "CustomersV3", select: "OrganizationName" });
      assert.equal(rows.rows[0].ReadBy, "carol@outlook.com");
    } finally {
      await client.close();
    }
  });

  it("refreshes tokens and retires the old access token", async () => {
    const provider = makeProvider(cloud, "alice");
    const client = await connectWithSignIn(serverUrl, provider);
    await client.close();
    const old = provider._tokens;
    const r = await fetch(`http://localhost:${port}/token`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ grant_type: "refresh_token", refresh_token: old.refresh_token, client_id: provider._client.client_id }) });
    assert.equal(r.status, 200);
    const fresh = await r.json();
    assert.notEqual(fresh.access_token, old.access_token);
    const initialize = (token) => fetch(serverUrl, { method: "POST", headers: { "content-type": "application/json", accept: "application/json, text/event-stream", authorization: `Bearer ${token}` },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-03-26", capabilities: {}, clientInfo: { name: "t", version: "0" } } }) });
    assert.equal((await initialize(old.access_token)).status, 401, "the old access token must stop working");
    assert.equal((await initialize(fresh.access_token)).status, 200, "the new one must work");
  });

  it("rejects a code exchange with the wrong PKCE verifier", async () => {
    const verifier = random();
    const state = random();
    const client = await registerClient(`http://localhost:${port}`);
    const authorize = new URL(`http://localhost:${port}/authorize`);
    authorize.search = new URLSearchParams({ client_id: client, redirect_uri: clientRedirect, response_type: "code", code_challenge: s256(verifier), code_challenge_method: "S256", state }).toString();
    const browser = makeBrowser();
    const toEntra = await authorizeInBrowser(browser, authorize);
    const toCallback = cloud.authorize(new URL(toEntra.headers.get("location")).searchParams, "alice");
    const toClient = new URL((await browser.fetch(toCallback)).headers.get("location"));
    assert.equal(toClient.searchParams.get("state"), state, "state must come back unchanged");
    const code = toClient.searchParams.get("code");
    const exchange = (code_verifier) => fetch(`http://localhost:${port}/token`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ grant_type: "authorization_code", code, client_id: client, redirect_uri: clientRedirect, code_verifier }) });
    const wrong = await exchange("not-the-verifier");
    assert.equal(wrong.status, 400);
    assert.equal((await wrong.json()).error, "invalid_grant");
    const again = await exchange(verifier);
    assert.equal(again.status, 400, "a code is single use, even after a failed attempt");
  });

  it("accepts a token issued by Entra directly, as scripts and advanced clients send it", async () => {
    const token = await cloud.userToken("bob", `api://${clientId}`);
    const client = new Client({ name: "direct", version: "0.0.0" });
    await client.connect(new StreamableHTTPClientTransport(new URL(serverUrl), { requestInit: { headers: { Authorization: `Bearer ${token}` } } }));
    try {
      const rows = await callTool(client, "query_entity", { entity: "CustomersV3", select: "OrganizationName" });
      assert.equal(rows.rows[0].ReadBy, "bob@example.com");
    } finally {
      await client.close();
    }
  });

  it("rejects an app-only token, which has no user to act for", async () => {
    const r = await mcpPost(serverUrl, await cloud.appToken(`api://${clientId}`), INITIALIZE);
    assert.equal(r.status, 401);
  });

  it("answers every user from their own caches, never from what another user's token read", async () => {
    const alice = await connectWithSignIn(serverUrl, makeProvider(cloud, "alice"));
    const eve = await connectWithSignIn(serverUrl, makeProvider(cloud, "eve"));
    try {
      const info = await callTool(alice, "environment_info");
      assert.ok(info.legalEntities.some((e) => e.id === "USMF"), "Alice fills her caches");
      const result = await eve.callTool({ name: "environment_info", arguments: {} });
      assert.equal(result.isError, true, "Eve has no F&O user, so she must not get Alice's cached entities");
      assert.match(result.content[0].text, /valid and set up correctly/);
      const frank = await connectWithSignIn(serverUrl, makeProvider(cloud, "frank"));
      try {
        const narrow = await callTool(frank, "environment_info");
        assert.equal(narrow.legalEntities, undefined, "Frank's role cannot read LegalEntities, so he must not get Alice's cached list");
        assert.match(narrow.problems.join(" "), /LegalEntities.*403/);
      } finally {
        await frank.close();
      }
    } finally {
      await alice.close();
      await eve.close();
    }
  });

  it("answers 404 for an unknown session, so the client starts a new one", async () => {
    const token = await cloud.userToken("bob", `api://${clientId}`);
    const r = await mcpPost(serverUrl, token, { jsonrpc: "2.0", id: 2, method: "tools/list" }, "no-such-session");
    assert.equal(r.status, 404);
    assert.equal((await r.json()).error.code, -32001);
  });

  it("does not let one user continue another user's session", async () => {
    const provider = makeProvider(cloud, "alice");
    const client = new Client({ name: "remote-test", version: "0.0.0" });
    let transport = new StreamableHTTPClientTransport(new URL(serverUrl), { authProvider: provider });
    try {
      await client.connect(transport);
    } catch (error) {
      if (!(error instanceof UnauthorizedError)) throw error;
      await transport.finishAuth(await provider.signIn);
      transport = new StreamableHTTPClientTransport(new URL(serverUrl), { authProvider: provider });
      await client.connect(transport);
    }
    try {
      assert.ok(transport.sessionId, "Alice has a session");
      const bob = await cloud.userToken("bob", `api://${clientId}`);
      const r = await mcpPost(serverUrl, bob, { jsonrpc: "2.0", id: 3, method: "tools/list" }, transport.sessionId);
      assert.equal(r.status, 404, "Bob's token must not open Alice's session");
      const del = await fetch(serverUrl, { method: "DELETE", headers: { authorization: `Bearer ${bob}`, "mcp-session-id": transport.sessionId } });
      assert.equal(del.status, 404, "nor end it");
      await client.listTools(); // Alice's session still works
    } finally {
      await client.close();
    }
  });

  it("refreshes after the access token expired, the usual case for an idle client", async () => {
    const provider = makeProvider(cloud, "dave");
    const client = await connectWithSignIn(serverUrl, provider);
    await client.close();
    const old = provider._tokens;
    await new Promise((r) => setTimeout(r, 2500)); // dave's Entra token lives two seconds
    assert.equal((await mcpPost(serverUrl, old.access_token, INITIALIZE)).status, 401, "the access token has expired");
    const r = await refreshAt(port, provider);
    assert.equal(r.status, 200, await r.clone().text());
    const fresh = await r.json();
    assert.equal((await mcpPost(serverUrl, fresh.access_token, INITIALIZE)).status, 200);
  });

  it("keeps the refresh token when Entra cannot be reached, so the client can try again", async () => {
    const provider = makeProvider(cloud, "alice");
    const client = await connectWithSignIn(serverUrl, provider);
    await client.close();
    cloud.faults.refreshOutages = 1;
    const failed = await refreshAt(port, provider);
    assert.equal(failed.status, 503);
    assert.equal((await failed.json()).error, "temporarily_unavailable");
    const retried = await refreshAt(port, provider);
    assert.equal(retried.status, 200, "the same refresh token works once Entra is back");
    const again = await refreshAt(port, provider);
    assert.equal((await again.json()).access_token, (await retried.json()).access_token, "right after the exchange it only repeats the same pair");
  });

  it("gives parallel refreshes with the same refresh token one shared answer", async () => {
    const provider = makeProvider(cloud, "alice");
    const client = await connectWithSignIn(serverUrl, provider);
    await client.close();
    cloud.faults.refreshDelayMs = 300; // both requests arrive while Entra is still answering the first
    try {
      const [a, b] = await Promise.all([refreshAt(port, provider), refreshAt(port, provider)]);
      assert.equal(a.status, 200);
      assert.equal(b.status, 200, "the second request must not get invalid_grant, the client would send the user to sign in");
      const [first, second] = [await a.json(), await b.json()];
      assert.equal(first.access_token, second.access_token, "both get the same new pair");
      assert.equal((await mcpPost(serverUrl, first.access_token, INITIALIZE)).status, 200);
    } finally {
      cloud.faults.refreshDelayMs = 0;
    }
  });

  it("revokes the whole sign in when a used refresh token comes back later", async () => {
    const provider = makeProvider(cloud, "alice");
    const client = await connectWithSignIn(serverUrl, provider);
    await client.close();
    const stolen = provider._tokens.refresh_token;
    const first = await refreshAt(port, provider);
    assert.equal(first.status, 200);
    const fresh = await first.json();
    await new Promise((r) => setTimeout(r, 5200)); // past the grace period for parallel requests
    const replay = await refreshAt(port, provider, stolen);
    assert.equal(replay.status, 400);
    assert.equal((await replay.json()).error, "invalid_grant");
    assert.equal((await mcpPost(serverUrl, fresh.access_token, INITIALIZE)).status, 401, "the pair issued after the stolen token is revoked too");
    assert.equal((await refreshAt(port, provider, fresh.refresh_token)).status, 400, "and so is its refresh token");
  });

  it("treats a 400 temporarily_unavailable from Entra as an outage, not as a refused grant", async () => {
    const provider = makeProvider(cloud, "alice");
    const client = await connectWithSignIn(serverUrl, provider);
    await client.close();
    cloud.faults.refreshOutages = 1;
    cloud.faults.refreshOutageStatus = 400;
    try {
      const failed = await refreshAt(port, provider);
      assert.equal(failed.status, 503);
      assert.equal((await refreshAt(port, provider)).status, 200, "the refresh token survived the outage");
    } finally {
      cloud.faults.refreshOutageStatus = 503;
    }
  });

  it("sends authorize errors back to the client when the redirect URI is valid", async () => {
    const authorize = new URL(`http://localhost:${port}/authorize`);
    const client = await registerClient(`http://localhost:${port}`);
    authorize.search = new URLSearchParams({ client_id: client, redirect_uri: clientRedirect, response_type: "token", code_challenge: "x", code_challenge_method: "S256", state: "s1" }).toString();
    const r = await fetch(authorize, { redirect: "manual" });
    assert.equal(r.status, 302);
    const back = new URL(r.headers.get("location"));
    assert.equal(`${back.origin}${back.pathname}`, clientRedirect);
    assert.equal(back.searchParams.get("error"), "unsupported_response_type");
    assert.equal(back.searchParams.get("state"), "s1");
    assert.equal(back.searchParams.get("iss"), `http://localhost:${port}`);
  });

  it("asks for consent on the first sign in of a client and not again in the same browser", async () => {
    const provider = makeProvider(cloud, "alice");
    const first = await connectWithSignIn(serverUrl, provider);
    await first.close();
    assert.deepEqual(provider.browser.history.map((h) => h.replace(/ \d+$/, "")), ["GET /authorize", "POST /consent", "GET /callback"]);
    assert.ok(provider.browser.cookie("fo_consent"), "the approval is remembered");

    // The client lost its tokens and signs in again with the same registration: straight to Entra this time.
    provider.saveTokens(undefined);
    provider.browser.history.length = 0;
    const second = await connectWithSignIn(serverUrl, provider);
    try {
      assert.deepEqual(provider.browser.history, ["GET /authorize 302", "GET /callback 302"]);
      assert.equal((await callTool(second, "environment_info")).user, "alice@example.com");
    } finally {
      await second.close();
    }
  });

  it("offers the write tools only to users with the MCP_WRITE_ROLE app role and ends a session once the user lost or gained the role", async () => {
    const writing = await startServer({ cloud, certFile: cert.certFile, env: { FO_ALLOW_WRITES: "1", FO_WRITE_ENTITIES: "CustomerGroups", MCP_WRITE_ROLE: "FO.Write" } });
    const writePort = writing.port;
    try {
      // Through the server's own sign in: Alice's Entra token carries the role, Bob's does not.
      const alice = await connectWithSignIn(writing.url, makeProvider(cloud, "alice"));
      const bob = await connectWithSignIn(writing.url, makeProvider(cloud, "bob"));
      try {
        assert.deepEqual((await alice.listTools()).tools.map((t) => t.name).sort(), [...WRITE_TOOLS, ...READ_TOOLS].sort());
        assert.equal((await callTool(alice, "environment_info")).writesEnabled, true);
        assert.deepEqual((await bob.listTools()).tools.map((t) => t.name).sort(), READ_TOOLS);
        const bobInfo = await callTool(bob, "environment_info");
        assert.equal(bobInfo.writesEnabled, false);
        // Not just writes off: the model can tell the user which role is missing and that it takes a new session.
        assert.equal(
          bobInfo.writeAccess,
          "create_record and update_record need the FO.Write app role, which the signed in user does not have. Once an administrator assigns it, " +
            "it comes with the next token, at the next sign in or token refresh, and the server then ends this session, so the client starts a new one with the write tools."
        );
        assert.equal("writeAccess" in (await callTool(alice, "environment_info")), false);
        const refused = await callToolRaw(bob, "create_record", { entity: "CustomerGroups", data: { CustomerGroupId: "99", Description: "No role" } });
        assert.equal(refused.isError, true, refused.text);
        assert.equal(cloud.seen.foRequests.some((r) => r.method === "POST" && r.path === "/data/CustomerGroups"), false, "nothing is written without the role");
      } finally {
        await alice.close();
        await bob.close();
      }

      // Tokens straight from Entra: the roles claim decides the same way.
      const audience = `api://${clientId}`;
      assert.deepEqual((await toolsOf(writing.url, await cloud.userToken("bob", audience, { roles: ["FO.Write"] }))).tools, [...WRITE_TOOLS, ...READ_TOOLS].sort());
      assert.deepEqual((await toolsOf(writing.url, await cloud.userToken("bob", audience, { roles: ["FO.Read", "fo.write"] }))).tools, READ_TOOLS);
      const { session } = await toolsOf(writing.url, await cloud.userToken("alice", audience));
      const withoutRole = await cloud.userToken("alice", audience, { roles: undefined });
      const lost = await mcpPost(writing.url, withoutRole, { jsonrpc: "2.0", id: 3, method: "tools/list" }, session);
      assert.equal(lost.status, 404, "the session with the write tools ends once the user's token lacks the role");
      await lost.text();
      const { session: readOnly, tools: readTools } = await toolsOf(writing.url, withoutRole);
      assert.deepEqual(readTools, READ_TOOLS, "the new session is read-only");

      // The role assigned later comes with the next token. The read-only session ends, so the client starts one with the tools.
      const granted = await cloud.userToken("alice", audience);
      const gained = await mcpPost(writing.url, granted, { jsonrpc: "2.0", id: 4, method: "tools/list" }, readOnly);
      assert.equal(gained.status, 404, "the read-only session ends once the user's token carries the role");
      await gained.text();
      assert.deepEqual((await toolsOf(writing.url, granted)).tools, [...WRITE_TOOLS, ...READ_TOOLS].sort(), "the new session has the write tools");

      // The consent page says that writes depend on the role.
      const client = await registerClient(`http://localhost:${writePort}`);
      const page = await makeBrowser().fetch(`http://localhost:${writePort}/authorize?${new URLSearchParams({
        client_id: client, redirect_uri: clientRedirect, response_type: "code", code_challenge: s256(random()), code_challenge_method: "S256" })}`);
      assert.match(await assertPage(page, 200), /Create and change records, if your account has the FO\.Write role/);
    } finally {
      await writing.stop();
    }
  });

  it("ends a session once a write role lost or gained arrives through the token refresh of the OAuth front, the way claude.ai users get it", async () => {
    const writing = await startServer({ cloud, certFile: cert.certFile, env: { FO_ALLOW_WRITES: "1", FO_WRITE_ENTITIES: "CustomerGroups", MCP_WRITE_ROLE: "FO.Write" } });
    const writePort = writing.port;
    const roles = cloud.users.alice.roles;
    const list = { jsonrpc: "2.0", id: 3, method: "tools/list" };
    try {
      const provider = makeProvider(cloud, "alice");
      const alice = await connectWithSignIn(writing.url, provider);
      try {
        assert.deepEqual((await alice.listTools()).tools.map((t) => t.name).sort(), [...WRITE_TOOLS, ...READ_TOOLS].sort());
        const session = alice.transportInUse.sessionId;
        // An administrator removes the role. The roles of the next proxy token come from the Entra token the refresh
        // brings, so the session with the write tools ends with that refresh and not at the next sign in.
        cloud.users.alice.roles = [];
        const lost = await refreshAt(writePort, provider);
        assert.equal(lost.status, 200, await lost.clone().text());
        const withoutRole = await lost.json();
        const ended = await mcpPost(writing.url, withoutRole.access_token, list, session);
        assert.equal(ended.status, 404, "the session with the write tools ends once the refreshed token lacks the role");
        await ended.text();
        const { session: readOnly, tools } = await toolsOf(writing.url, withoutRole.access_token);
        assert.deepEqual(tools, READ_TOOLS, "the new session is read-only");

        // The role assigned again comes with the refresh after that. The read-only session ends the same way.
        cloud.users.alice.roles = ["FO.Write"];
        const regained = await refreshAt(writePort, provider, withoutRole.refresh_token);
        assert.equal(regained.status, 200, await regained.clone().text());
        const withRole = await regained.json();
        const gained = await mcpPost(writing.url, withRole.access_token, list, readOnly);
        assert.equal(gained.status, 404, "the read-only session ends once the refreshed token carries the role");
        await gained.text();
        assert.deepEqual((await toolsOf(writing.url, withRole.access_token)).tools, [...WRITE_TOOLS, ...READ_TOOLS].sort(), "the new session has the write tools");
      } finally {
        await alice.close();
      }
    } finally {
      cloud.users.alice.roles = roles;
      await writing.stop();
    }
  });

  it("offers the write tools to every user when writes are on and MCP_WRITE_ROLE is not set", async () => {
    const writing = await startServer({ cloud, certFile: cert.certFile, env: { FO_ALLOW_WRITES: "1", FO_WRITE_ENTITIES: "CustomerGroups" } });
    const writePort = writing.port;
    try {
      assert.deepEqual((await toolsOf(writing.url, await cloud.userToken("bob", `api://${clientId}`))).tools, [...WRITE_TOOLS, ...READ_TOOLS].sort());
      const client = await registerClient(`http://localhost:${writePort}`);
      const page = await makeBrowser().fetch(`http://localhost:${writePort}/authorize?${new URLSearchParams({
        client_id: client, redirect_uri: clientRedirect, response_type: "code", code_challenge: s256(random()), code_challenge_method: "S256" })}`);
      const html = await assertPage(page, 200);
      assert.match(html, /Create and change records<br>/);
      assert.doesNotMatch(html, /if your account has/);
    } finally {
      await writing.stop();
    }
  });
});
