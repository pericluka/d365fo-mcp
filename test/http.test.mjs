// Tests of the HTTP layer of the remote server (dist/http.js): MCP sessions and their limits, the Host header check,
// the public routes, the request log, CORS, bad JSON, the abuse limits, the listen address, configuration it refuses,
// keep-alive, clock skew and shutdown. Everything runs against the fake Entra and fake F&O of test/support.mjs. Run with node --test test/http.test.mjs.
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { Agent, createServer as createHttpServer, request } from "node:http";
import { connect } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, beforeEach, describe, it } from "node:test";
import { RateLimiter } from "../dist/oauth.js";
import {
  assertPage, authorizeInBrowser, clientId, clientRedirect, consentForm, copyBuiltServer, ENTRA_TRACE, freePort, INITIALIZE, listenOn, logLine, makeBrowser, makeCert,
  mcpPost, NO_OPENSSL, noSignals, postConsent, projectDir, random, randomIp, registerClient, s256, serverEnv, serverVariables, sleep, startFakeCloud, startServer, SUITE_TIMEOUT,
} from "./support.mjs";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const audience = `api://${clientId}`;
const PING = { jsonrpc: "2.0", id: 7, method: "ping" };
const TOOLS_LIST = { jsonrpc: "2.0", id: 8, method: "tools/list" };

/** The first JSON-RPC message of an answer, which the transport sends as an SSE stream or as plain JSON. */
async function rpcBody(response) {
  const text = await response.text();
  if ((response.headers.get("content-type") ?? "").includes("text/event-stream")) {
    const data = text.split("\n").filter((l) => l.startsWith("data: ")).map((l) => JSON.parse(l.slice(6)));
    return data[0];
  }
  return text ? JSON.parse(text) : undefined;
}

/** A plain HTTP request with full control of the headers, Host and Origin included, which fetch may not send as given. */
function rawRequest(port, { method = "GET", path = "/", headers = {}, body } = {}) {
  return new Promise((resolve, reject) => {
    const req = request({ host: "localhost", port, method, path, headers }, (res) => {
      const chunks = [];
      res.on("data", (c) => chunks.push(c));
      res.on("end", () => resolve({ status: res.statusCode, headers: res.headers, text: Buffer.concat(chunks).toString("utf8") }));
    });
    req.on("error", reject);
    if (body !== undefined) req.write(body);
    req.end();
  });
}

/** Run dist/http.js with a configuration it must refuse, and return its exit code and output. */
function runRefused(env) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [join(projectDir, "dist/http.js")], { cwd: projectDir, env, stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (d) => (stdout += d));
    child.stderr.on("data", (d) => (stderr += d));
    const timer = setTimeout(() => child.kill(), 10_000);
    child.on("exit", (code) => {
      clearTimeout(timer);
      resolve({ code, stdout, stderr });
    });
  });
}

/** Run requests in batches of `width` at once and return their responses in order. */
async function inBatches(count, width, send) {
  const responses = [];
  for (let i = 0; i < count; i += width) {
    const batch = await Promise.all(Array.from({ length: Math.min(width, count - i) }, (_, j) => send(i + j)));
    for (const r of batch) await r.text?.();
    responses.push(...batch);
  }
  return responses;
}

describe("remote server HTTP layer and MCP sessions", { timeout: SUITE_TIMEOUT, skip: NO_OPENSSL }, () => {
  let cert, cloud, server, serverUrl, port;

  /** A direct Entra token for a user with an object ID of its own, so no other test's sessions count towards its limit. */
  const freshUser = (user) => cloud.userToken(user, audience, { oid: `oid-${user}-${random()}` });

  /** Initialize a session and return its ID, failing the test when the server does not create one. */
  async function openSession(token, url = serverUrl) {
    const r = await mcpPost(url, token, INITIALIZE);
    const body = await rpcBody(r);
    assert.equal(r.status, 200, JSON.stringify(body));
    const id = r.headers.get("mcp-session-id");
    assert.match(id ?? "", UUID, "initialize must return an Mcp-Session-Id");
    return id;
  }

  /** Send a ping in a session and return the status, reading the body so the connection is freed. */
  async function pingStatus(token, sessionId, url = serverUrl) {
    const r = await mcpPost(url, token, PING, sessionId);
    await r.text();
    return r.status;
  }

  /**
   * Send an update_record in a session and hold its PATCH at the fake F&O, which has applied the change by then.
   * Returns the pending answer and release(), which lets F&O answer. The server needs writes on for CustomerGroups.
   */
  async function holdUpdate(url, token, sessionId, description) {
    let answerPatch;
    cloud.faults.afterPatch = () => new Promise((resolve) => (answerPatch = resolve));
    const call = { jsonrpc: "2.0", id: 9, method: "tools/call", params: { name: "update_record", arguments: { entity: "CustomerGroups", key: { CustomerGroupId: "10" }, data: { Description: description } } } };
    const answer = mcpPost(url, token, call, sessionId);
    const deadline = Date.now() + 5000;
    while (!answerPatch) {
      assert.ok(Date.now() < deadline, "the update reaches F&O");
      await sleep(10);
    }
    cloud.faults.afterPatch = undefined;
    return { answer, release: () => answerPatch() };
  }

  /** The audit line of the last update_record a server wrote, or undefined. */
  const updateAudit = (target) => target.log().split("\n").filter((l) => l.startsWith("{")).map((l) => JSON.parse(l)).findLast((e) => e.tool === "update_record");

  /** Settings of a server with writes on for CustomerGroups, for users with the FO.Write role. */
  const WRITE_ROLE_ENV = { FO_ALLOW_WRITES: "1", FO_WRITE_ENTITIES: "CustomerGroups", MCP_WRITE_ROLE: "FO.Write" };

  /** A valid authorize URL of a client, for the limits of the sign in pages. */
  const authorizeUrl = (client, overrides = {}) =>
    `http://localhost:${port}/authorize?${new URLSearchParams({ client_id: client, redirect_uri: clientRedirect, response_type: "code", code_challenge: s256(random()), code_challenge_method: "S256", state: random(), ...overrides })}`;

  before(async () => {
    cert = makeCert();
    cloud = await startFakeCloud(cert.dir);
    port = await freePort();
    server = await startServer({ port, cloud, certFile: cert.certFile, env: { MCP_PUBLIC_URL: `http://localhost:${port}/mcp`, MCP_ALLOWED_HOSTS: "Extra.Example" } });
    serverUrl = server.url;
  });

  after(async () => {
    await server?.stop();
    await cloud?.close();
    cert?.remove();
  });

  beforeEach(() => cloud.reset());

  it("creates a session on initialize with a valid token and returns its Mcp-Session-Id", async () => {
    const token = await freshUser("alice");
    const r = await mcpPost(serverUrl, token, INITIALIZE);
    assert.equal(r.status, 200);
    const id = r.headers.get("mcp-session-id");
    assert.match(id ?? "", UUID);
    const init = await rpcBody(r);
    assert.equal(init.id, 1);
    assert.equal(init.result.serverInfo.name, "fo-mcp");

    // The session works: tools/list in it answers with the read-only tools.
    const list = await mcpPost(serverUrl, token, TOOLS_LIST, id);
    assert.equal(list.status, 200);
    const tools = (await rpcBody(list)).result.tools.map((t) => t.name).sort();
    assert.deepEqual(tools, ["describe_entity", "environment_info", "query_entity", "search_entities"]);
  });

  it("answers 400 to a POST without a session that is not initialize, creates no session and calls nothing in F&O", async () => {
    const token = await freshUser("alice");
    for (const body of [TOOLS_LIST, { jsonrpc: "2.0", id: 3, method: "tools/call", params: { name: "environment_info", arguments: {} } }]) {
      const r = await mcpPost(serverUrl, token, body);
      assert.equal(r.status, 400);
      assert.equal(r.headers.get("mcp-session-id"), null, "no session ID may be handed out");
      const json = await r.json();
      assert.equal(json.error.code, -32000);
      assert.match(json.error.message, /initialize/);
    }
    assert.deepEqual(cloud.seen.foRequests, [], "nothing may reach F&O without a session");
  });

  it("answers 404 to GET and DELETE with an unknown session or none at all", async () => {
    const token = await freshUser("alice");
    for (const method of ["GET", "DELETE"]) {
      for (const sessionId of ["no-such-session", "00000000-0000-4000-8000-000000000000", undefined]) {
        const r = await fetch(serverUrl, { method, headers: { authorization: `Bearer ${token}`, accept: "text/event-stream", ...(sessionId ? { "mcp-session-id": sessionId } : {}) } });
        assert.equal(r.status, 404, `${method} with session ${sessionId}`);
        assert.equal((await r.json()).error.code, -32001);
      }
    }
  });

  it("ends a session on DELETE, after which its ID answers 404 to POST, GET and DELETE", async () => {
    const token = await freshUser("alice");
    const id = await openSession(token);
    assert.equal(await pingStatus(token, id), 200, "the session works before DELETE");

    const del = await fetch(serverUrl, { method: "DELETE", headers: { authorization: `Bearer ${token}`, "mcp-session-id": id } });
    assert.equal(del.status, 200);

    const post = await mcpPost(serverUrl, token, PING, id);
    assert.equal(post.status, 404);
    assert.equal((await post.json()).error.code, -32001);
    for (const method of ["GET", "DELETE"]) {
      const r = await fetch(serverUrl, { method, headers: { authorization: `Bearer ${token}`, accept: "text/event-stream", "mcp-session-id": id } });
      assert.equal(r.status, 404, `${method} after DELETE`);
      await r.text();
    }
  });

  it("keeps at most 10 sessions per user: the 11th initialize closes the least recently used one", async () => {
    const token = await freshUser("alice");
    const ids = [];
    for (let i = 0; i < 10; i++) ids.push(await openSession(token));
    await sleep(5);
    // Using the first session makes the second one the least recently used.
    assert.equal(await pingStatus(token, ids[0]), 200);

    const eleventh = await openSession(token);
    assert.equal(await pingStatus(token, ids[1]), 404, "the least recently used session is closed");
    assert.equal(await pingStatus(token, ids[0]), 200, "the most recently used session still works");
    assert.equal(await pingStatus(token, eleventh), 200, "the new session works");
    for (const id of ids.slice(2)) assert.equal(await pingStatus(token, id), 200, "the other sessions are untouched");
  });

  it("leaves another user's sessions alone when a user goes past the limit", async () => {
    const bob = await freshUser("bob");
    const alice = await freshUser("alice");
    // Bob's session is the oldest on the server, so an eviction that ignored the user would close it first.
    const bobSession = await openSession(bob);
    await sleep(5);
    const aliceSessions = [];
    for (let i = 0; i < 11; i++) aliceSessions.push(await openSession(alice));
    assert.equal(await pingStatus(bob, bobSession), 200, "Bob's session must survive Alice's eleventh initialize");
    assert.equal(await pingStatus(alice, aliceSessions[0]), 404, "Alice's oldest session made room instead");
    for (const id of aliceSessions.slice(1)) assert.equal(await pingStatus(alice, id), 200);
  });

  it("keeps at most 500 sessions on the whole server: the 501st initialize closes the least recently used one of any user", async () => {
    // A server of its own, so the sessions the other tests leave behind are not the ones that make room.
    const crowded = await startServer({ cloud, certFile: cert.certFile });
    try {
      // Ten sessions each, the limit per user, for 50 users fill the server exactly. The 51st user brings the 501st.
      const users = await Promise.all(Array.from({ length: 51 }, (_, i) => cloud.userToken(i % 2 ? "bob" : "alice", audience, { oid: `oid-crowd-${i}-${random()}` })));
      const open = (i) => openSession(users[Math.floor(i / 10)], crowded.url);
      const first = await open(0);
      await sleep(5);
      const second = await open(1);
      await sleep(5);
      for (let i = 2; i < 500; i += 25) await Promise.all(Array.from({ length: Math.min(25, 500 - i) }, (_, j) => open(i + j)));
      const fiveHundredFirst = await open(500);
      assert.equal(await pingStatus(users[0], first, crowded.url), 404, "the least recently used session of the server is closed, although its user holds two");
      assert.equal(await pingStatus(users[0], second, crowded.url), 200, "the 500th initialize closed nothing");
      assert.equal(await pingStatus(users[50], fiveHundredFirst, crowded.url), 200, "the new session works");
    } finally {
      await crowded.stop();
    }
  });

  it("answers 404 when a session ID comes with another user's token, without touching the session or F&O", async () => {
    const alice = await freshUser("alice");
    const id = await openSession(alice);
    const bob = await cloud.userToken("bob", audience);
    const call = { jsonrpc: "2.0", id: 4, method: "tools/call", params: { name: "query_entity", arguments: { entity: "CustomersV3", select: "CustomerAccount" } } };
    const post = await mcpPost(serverUrl, bob, call, id);
    assert.equal(post.status, 404);
    assert.equal((await post.json()).error.code, -32001);
    for (const method of ["GET", "DELETE"]) {
      const r = await fetch(serverUrl, { method, headers: { authorization: `Bearer ${bob}`, accept: "text/event-stream", "mcp-session-id": id } });
      assert.equal(r.status, 404, `${method} with Bob's token`);
      await r.text();
    }
    assert.deepEqual(cloud.seen.foRequests, [], "Bob's call must not reach F&O");

    // Alice's session still works and runs as Alice.
    const own = await mcpPost(serverUrl, alice, call, id);
    assert.equal(own.status, 200);
    const result = await rpcBody(own);
    assert.equal(result.result.isError ?? false, false, JSON.stringify(result));
    assert.ok(cloud.seen.foRequests.length > 0);
    assert.ok(cloud.seen.foRequests.every((r) => r.user === "alice@example.com"), JSON.stringify(cloud.seen.foRequests));
  });

  it("answers for its public host and the extra allowed hosts and refuses any other Host with 403, except at /health", async () => {
    for (const host of [`localhost:${port}`, "localhost", "extra.example", "Extra.Example", "extra.example:443"]) {
      const r = await rawRequest(port, { path: "/", headers: { host } });
      assert.equal(r.status, 200, `Host ${host}: ${r.text}`);
      assert.equal(JSON.parse(r.text).name, "fo-mcp");
    }
    for (const host of ["evil.example", `evil.example:${port}`, "localhost.evil.example", "extra.example.evil.example", "10.0.0.5:3000"]) {
      for (const path of ["/", "/.well-known/oauth-authorization-server", "/authorize"]) {
        const r = await rawRequest(port, { path, headers: { host } });
        assert.equal(r.status, 403, `Host ${host} at ${path}`);
        assert.match(JSON.parse(r.text).error.message, /Invalid Host/);
      }
    }
    // A liveness or readiness probe sends the replica's own address as Host, and /health tells nothing anyway.
    for (const host of ["10.0.0.5:3000", "127.0.0.1", "evil.example"]) {
      const r = await rawRequest(port, { path: "/health", headers: { host } });
      assert.equal(r.status, 200, `/health with Host ${host}: ${r.text}`);
      assert.equal(JSON.parse(r.text).status, "ok");
    }
    // The check comes before the MCP endpoint too: a valid token through a foreign host opens no session.
    const token = await freshUser("alice");
    const r = await rawRequest(port, {
      method: "POST", path: "/mcp", body: JSON.stringify(INITIALIZE),
      headers: { host: "evil.example", "content-type": "application/json", accept: "application/json, text/event-stream", authorization: `Bearer ${token}` },
    });
    assert.equal(r.status, 403);
    assert.equal(r.headers["mcp-session-id"], undefined);
  });

  it("answers /health without a token with its status, name and version only, and never names the F&O environment", async () => {
    const r = await fetch(`http://localhost:${port}/health`);
    assert.equal(r.status, 200);
    const text = await r.text();
    const json = JSON.parse(text);
    assert.deepEqual(Object.keys(json).sort(), ["name", "status", "version"]);
    assert.equal(json.status, "ok");
    assert.equal(json.name, "fo-mcp");
    assert.match(json.version, /^\d+\.\d+\.\d+/);
    assert.equal(r.headers.get("x-powered-by"), null);
    const cloudHost = new URL(cloud.foUrl).host;
    for (const secret of [cloud.foUrl, cloudHost]) {
      assert.ok(!text.includes(secret), `/health must not contain ${secret}: ${text}`);
      for (const [name, value] of r.headers) assert.ok(!value.includes(secret), `header ${name} must not contain ${secret}`);
    }
  });

  it("answers GET / with 200 and the MCP URL", async () => {
    const r = await fetch(`http://localhost:${port}/`);
    assert.equal(r.status, 200);
    const json = await r.json();
    assert.equal(json.name, "fo-mcp");
    assert.equal(json.mcp, serverUrl);
    assert.equal(json.mcp, `http://localhost:${port}/mcp`);
    assert.ok(!JSON.stringify(json).includes(new URL(cloud.foUrl).host), "GET / must not name the F&O environment");
  });

  it("serves MCP at / when the public URL has the path /, so GET / answers 401 instead of the info JSON", async () => {
    const rootPort = await freePort();
    const rootServer = await startServer({ port: rootPort, cloud, certFile: cert.certFile, env: { MCP_PUBLIC_URL: `http://localhost:${rootPort}/` } });
    try {
      const r = await fetch(`http://localhost:${rootPort}/`);
      assert.equal(r.status, 401);
      assert.match(r.headers.get("www-authenticate") ?? "", new RegExp(`resource_metadata="http://localhost:${rootPort}/\\.well-known/oauth-protected-resource"`));
      const body = await r.json();
      assert.equal(body.mcp, undefined, "the info JSON must not be served at the MCP endpoint");
      assert.equal(body.error, "invalid_token");

      // With a token, / is the MCP endpoint: initialize opens a session there.
      const token = await freshUser("alice");
      const rootUrl = `http://localhost:${rootPort}/`;
      const id = await openSession(token, rootUrl);
      const list = await mcpPost(rootUrl, token, TOOLS_LIST, id);
      assert.equal(list.status, 200);
      assert.equal((await rpcBody(list)).result.tools.length, 4);
      const metadata = await (await fetch(`http://localhost:${rootPort}/.well-known/oauth-protected-resource`)).json();
      assert.equal(metadata.resource, rootUrl);
    } finally {
      await rootServer.stop();
    }
  });

  it("serves the MCP endpoint at the exact path of MCP_PUBLIC_URL only, not with a trailing slash or in another case", async () => {
    // Express would serve /mcp/ and /MCP too, but a session stream there would count as a request in flight that never
    // ends, so a SIGTERM would wait the full 25 s, and its errors would come in the OAuth shape instead of JSON-RPC.
    const token = await freshUser("alice");
    for (const path of ["/mcp/", "/MCP", "/Mcp"]) {
      const post = await mcpPost(`http://localhost:${port}${path}`, token, INITIALIZE);
      await post.text();
      assert.equal(post.status, 404, `POST ${path}`);
      assert.equal(post.headers.get("mcp-session-id"), null, `no session is opened at ${path}`);
      const stream = new AbortController();
      const sse = await fetch(`http://localhost:${port}${path}`, { headers: { authorization: `Bearer ${token}`, accept: "text/event-stream" }, signal: stream.signal });
      stream.abort();
      assert.equal(sse.status, 404, `GET ${path}`);
    }
    // The well-known routes the SDK mounts as prefixes, and every other route, stay served.
    for (const path of ["/.well-known/oauth-protected-resource/mcp", "/.well-known/oauth-protected-resource", "/.well-known/oauth-authorization-server", "/health", "/"]) {
      const r = await fetch(`http://localhost:${port}${path}`);
      await r.text();
      assert.equal(r.status, 200, path);
    }
    assert.equal(await pingStatus(token, await openSession(token)), 200, "the exact path works");
  });

  it("logs the last X-Forwarded-For address, the one the ingress appended, and not what the client put in front", async () => {
    const agent = `xff-test-${random()}`;
    const r = await fetch(`http://localhost:${port}/health`, { headers: { "x-forwarded-for": "1.2.3.4, 5.6.7.8", "user-agent": agent } });
    assert.equal(r.status, 200);
    await r.text();
    const line = await logLine(server, agent);
    assert.match(line, new RegExp(`^GET /health 200 \\d+ ms 5\\.6\\.7\\.8 - ${agent}$`));
    assert.ok(!line.includes("1.2.3.4"), line);
  });

  it("takes the client address from as many X-Forwarded-For hops as MCP_TRUST_PROXY says, without a port, or from the connection with 0", async () => {
    const logged = async (target, xff) => {
      const agent = `hops-${random()}`;
      await (await fetch(`http://localhost:${target.port}/health`, { headers: { "x-forwarded-for": xff, "user-agent": agent } })).text();
      // The address comes before the session, a dash outside one, then the user agent.
      return (await logLine(target, agent)).split(" ").at(-3);
    };
    // The default trusts the one proxy of the Container Apps ingress, and a proxy that appends address:port changes nothing.
    assert.match(server.log(), /client addresses from X-Forwarded-For behind 1 proxy$/m);
    assert.equal(await logged(server, "1.1.1.1, 203.0.113.9:51234"), "203.0.113.9");
    assert.equal(await logged(server, "[2001:db8::7]:443"), "2001:db8::7");

    const behindTwo = await startServer({ cloud, certFile: cert.certFile, env: { MCP_TRUST_PROXY: "2" } });
    const direct = await startServer({ cloud, certFile: cert.certFile, env: { MCP_TRUST_PROXY: "0" } });
    try {
      assert.match(behindTwo.log(), /client addresses from X-Forwarded-For behind 2 proxies$/m);
      assert.equal(await logged(behindTwo, "6.6.6.6, 2.2.2.2, 3.3.3.3"), "2.2.2.2", "a WAF in front of the ingress adds a hop");
      assert.equal(await logged(behindTwo, "4.4.4.4"), "4.4.4.4", "a request with fewer hops keeps the first one");
      assert.match(direct.log(), /client addresses from the connection$/m);
      assert.equal(await logged(direct, "5.5.5.5"), "127.0.0.1");
      // Without a trusted proxy a client cannot pick its own key for the limits per address.
      const client = await registerClient(`http://localhost:${direct.port}`);
      const url = `http://localhost:${direct.port}/authorize?${new URLSearchParams({ client_id: client, redirect_uri: clientRedirect, response_type: "code", code_challenge: s256(random()), code_challenge_method: "S256" })}`;
      const answers = await inBatches(31, 31, () => fetch(url, { headers: { "x-forwarded-for": randomIp() } }));
      assert.deepEqual(answers.map((r) => r.status).sort(), [...Array(30).fill(200), 429]);
    } finally {
      await behindTwo.stop();
      await direct.stop();
    }
  });

  it("names the MCP session in the request line, the key it shares with the audit line, so a tool call can be tied to an address", async () => {
    const token = await freshUser("alice");
    const agent = `session-log-${random()}`;
    const headers = { "x-forwarded-for": "1.2.3.4, 203.0.113.5", "user-agent": agent };
    const init = await mcpPost(serverUrl, token, INITIALIZE, undefined, headers);
    await init.text();
    const id = init.headers.get("mcp-session-id");
    assert.match(id ?? "", UUID);
    const call = { jsonrpc: "2.0", id: 5, method: "tools/call", params: { name: "environment_info", arguments: {} } };
    await (await mcpPost(serverUrl, token, call, id, headers)).text();
    const marker = `log-marker-${random()}`;
    await (await fetch(`http://localhost:${port}/health`, { headers: { "user-agent": marker } })).text();
    await logLine(server, marker);
    // The initialize has the ID from its answer, the call from its request, so every line of the session names it.
    const lines = server.log().split("\n").filter((l) => l.endsWith(` ${agent}`));
    assert.equal(lines.length, 2, lines.join("\n"));
    for (const line of lines) assert.match(line, new RegExp(`^POST /mcp 200 \\d+ ms 203\\.0\\.113\\.5 ${id} ${agent}$`));
    const audit = server.log().split("\n").filter((l) => l.startsWith("{")).map((l) => JSON.parse(l)).filter((e) => e.session === id);
    assert.deepEqual(audit.map((e) => e.tool), ["environment_info"], "the audit line of the call carries the same session");
    assert.match(await logLine(server, marker), new RegExp(`^GET /health 200 \\d+ ms \\S+ - ${marker}$`), "a request outside a session shows a dash");
    // An ID the server did not accept is not printed, with or without a token: the field is the key to the audit lines,
    // and a caller could otherwise write any text into it, another user's session ID included.
    const forged = `forged-${random()}`;
    const refused = await mcpPost(serverUrl, token, call, "made up session", { "user-agent": forged });
    assert.equal(refused.status, 404);
    assert.match(await logLine(server, forged), new RegExp(`^POST /mcp 404 \\d+ ms \\S+ - ${forged}$`));
    const bob = await freshUser("bob");
    const stranger = `stranger-${random()}`;
    assert.equal((await mcpPost(serverUrl, bob, call, id, { "user-agent": stranger })).status, 404, "another user's session");
    assert.match(await logLine(server, stranger), new RegExp(`^POST /mcp 404 \\d+ ms \\S+ - ${stranger}$`));
    // Text of the caller cannot draw a second entry into the line. A counted hop that is no address is not taken for one,
    // and the user agent loses what a log reader may break a line at.
    const drawn = `drawn-${random()}`;
    await (await fetch(`http://localhost:${port}/health`, {
      headers: { "x-forwarded-for": `1.1.1.1, 9.9.9.9 ${id} Mozilla #`, "user-agent": `${drawn}\u0085GET /mcp 200 3 ms 6.6.6.6 ${id} forged\t!` },
    })).text();
    const line = await logLine(server, drawn);
    assert.match(line, new RegExp(`^GET /health 200 \\d+ ms (127\\.0\\.0\\.1|::1|::ffff:127\\.0\\.0\\.1) - ${drawn} GET /mcp 200 3 ms 6\\.6\\.6\\.6 ${id} forged !$`));
    // The public metadata names no F&O host unless FO_NAME was set, the consent page withholds it for the same reason.
    const metadata = await (await fetch(`http://localhost:${port}/.well-known/oauth-protected-resource/mcp`)).json();
    assert.equal(metadata.resource_name, "fo-mcp");
    assert.equal(JSON.stringify(metadata).includes(new URL(cloud.foUrl).host), false);
  });

  it("never writes a token, a code, a cookie or a CSRF token to the log, and audits tool calls with the user, client and session", async () => {
    // The browser and every request come from behind the ingress: the server must log 5.6.7.8, never 1.2.3.4.
    const headers = { "x-forwarded-for": "1.2.3.4, 5.6.7.8" };
    const browser = makeBrowser({ ip: "1.2.3.4, 5.6.7.8" });
    const client = await registerClient(`http://localhost:${port}`);
    const verifier = `${random()}${random()}`;
    const clientState = `state-${random()}`;
    const page = await browser.fetch(authorizeUrl(client, { code_challenge: s256(verifier), state: clientState }));
    const form = consentForm(await assertPage(page, 200));
    const toEntra = await postConsent(browser, `http://localhost:${port}`, form);
    assert.equal(toEntra.status, 303);
    const entraParams = new URL(toEntra.headers.get("location")).searchParams;
    const toCallback = new URL(cloud.authorize(entraParams, "alice"));
    const cookies = Object.fromEntries([...browser.jar].map(([name, c]) => [name, c.value]));
    const toClient = await browser.fetch(toCallback);
    assert.equal(toClient.status, 302);
    const code = new URL(toClient.headers.get("location")).searchParams.get("code");
    assert.ok(code);

    const post = (path, form) => fetch(`http://localhost:${port}${path}`, { method: "POST", headers: { ...headers, "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams(form) });
    const first = await post("/token", { grant_type: "authorization_code", code, client_id: client, redirect_uri: clientRedirect, code_verifier: verifier });
    assert.equal(first.status, 200);
    const pair = await first.json();
    const second = await post("/token", { grant_type: "refresh_token", refresh_token: pair.refresh_token, client_id: client });
    assert.equal(second.status, 200);
    const refreshed = await second.json();
    const call = { jsonrpc: "2.0", id: 5, method: "tools/call", params: { name: "environment_info", arguments: {} } };
    const init = await mcpPost(serverUrl, refreshed.access_token, INITIALIZE, undefined, headers);
    assert.equal(init.status, 200);
    await init.text();
    const proxySession = init.headers.get("mcp-session-id");
    const proxyCall = await mcpPost(serverUrl, refreshed.access_token, call, proxySession, headers);
    assert.equal((await rpcBody(proxyCall)).result.isError ?? false, false);
    const direct = await cloud.userToken("bob", audience);
    const directInit = await mcpPost(serverUrl, direct, INITIALIZE, undefined, headers);
    assert.equal(directInit.status, 200);
    await directInit.text();
    const directSession = directInit.headers.get("mcp-session-id");
    await (await mcpPost(serverUrl, direct, call, directSession, headers)).text();
    const bogus = `bogus-${random()}`;
    const refused = await mcpPost(serverUrl, bogus, INITIALIZE, undefined, headers);
    assert.equal(refused.status, 401);
    await refused.text();
    // Entra refuses the next refresh: its full text goes to the log, and nothing of the request with it.
    cloud.faults.refreshRefusals = 1;
    const dead = await post("/token", { grant_type: "refresh_token", refresh_token: refreshed.refresh_token, client_id: client });
    assert.equal(dead.status, 400);
    assert.equal((await post("/revoke", { token: pair.access_token, client_id: client })).status, 200);

    // A last request marks the point where every line above has been written.
    const marker = `log-marker-${random()}`;
    await (await fetch(`http://localhost:${port}/health`, { headers: { "user-agent": marker } })).text();
    await logLine(server, marker);
    const log = server.log();
    for (const expected of ["GET /authorize 200", "POST /consent 303", "GET /callback 302", "POST /token 200", "POST /mcp 200", "POST /mcp 401", "POST /token 400", "POST /revoke 200"]) {
      assert.match(log, new RegExp(`^${expected} \\d+ ms 5\\.6\\.7\\.8 `, "m"), `a log line for ${expected}`);
    }
    assert.match(log, new RegExp(`Entra refused the refresh_token request with 400 invalid_grant: AADSTS70043.*${ENTRA_TRACE}`));

    // One audit line per tool call, with who called it from which client in which session.
    const audit = log.split("\n").filter((l) => l.startsWith("{")).map((l) => JSON.parse(l)).filter((e) => e.event === "tool" && [proxySession, directSession].includes(e.session));
    assert.deepEqual(
      audit.map((e) => [e.tool, e.user, e.oid, e.client, e.session, e.ok]),
      [["environment_info", "alice@example.com", "oid-alice", client, proxySession, true], ["environment_info", "bob@example.com", "oid-bob", clientId, directSession, true]]
    );

    const secrets = {
      verifier, codeChallenge: s256(verifier), clientState, entraState: entraParams.get("state"), entraCode: toCallback.searchParams.get("code"), code,
      csrfToken: form.csrf, ...cookies, accessToken: pair.access_token, refreshToken: pair.refresh_token, refreshedAccessToken: refreshed.access_token,
      refreshedRefreshToken: refreshed.refresh_token, directToken: direct, bogusToken: bogus,
    };
    assert.ok(cookies.fo_csrf && cookies.fo_consent && Object.keys(cookies).some((n) => n.startsWith("fo_signin_")), JSON.stringify(Object.keys(cookies)));
    for (const [name, value] of Object.entries(secrets)) {
      assert.ok(value, `${name} is known to the test`);
      assert.ok(!log.includes(value), `the log must not contain the ${name}`);
    }
    assert.doesNotMatch(log, /eyJ[\w-]+\.eyJ[\w-]+\.[\w-]+/, "no JWT at all, the Entra tokens of the users included");
    assert.doesNotMatch(log, /fo-token-for|entra-refresh-|entra-code-/, "no F&O token, Entra refresh token or Entra code");
    assert.ok(!log.includes("1.2.3.4"), "the client supplied address must never be logged");
  });

  it("answers a CORS preflight from claude.ai with 204 and exposes Mcp-Session-Id and WWW-Authenticate", async () => {
    const r = await rawRequest(port, {
      method: "OPTIONS", path: "/mcp",
      headers: { origin: "https://claude.ai", "access-control-request-method": "POST", "access-control-request-headers": "authorization, content-type, mcp-session-id, mcp-protocol-version" },
    });
    assert.equal(r.status, 204);
    assert.ok(["*", "https://claude.ai"].includes(r.headers["access-control-allow-origin"]), r.headers["access-control-allow-origin"]);
    const exposed = (r.headers["access-control-expose-headers"] ?? "").toLowerCase().split(",").map((h) => h.trim());
    assert.ok(exposed.includes("mcp-session-id"), exposed.join(","));
    assert.ok(exposed.includes("www-authenticate"), exposed.join(","));
    assert.match(r.headers["access-control-allow-methods"] ?? "", /POST/);
    assert.match(r.headers["access-control-allow-methods"] ?? "", /DELETE/);
    for (const h of ["authorization", "mcp-session-id"]) assert.match(r.headers["access-control-allow-headers"] ?? "", new RegExp(h, "i"));

    // The real answers carry the same headers, so a browser client can read the session ID and the 401 challenge.
    const token = await freshUser("alice");
    const init = await mcpPost(serverUrl, token, INITIALIZE, undefined, { origin: "https://claude.ai" });
    await init.text();
    assert.equal(init.status, 200);
    assert.ok(["*", "https://claude.ai"].includes(init.headers.get("access-control-allow-origin")));
    assert.match(init.headers.get("access-control-expose-headers") ?? "", /Mcp-Session-Id/i);
    const challenge = await fetch(serverUrl, { method: "POST", headers: { origin: "https://claude.ai", "content-type": "application/json" }, body: JSON.stringify(INITIALIZE) });
    await challenge.text();
    assert.equal(challenge.status, 401);
    assert.ok(challenge.headers.get("access-control-allow-origin"));
    assert.match(challenge.headers.get("access-control-expose-headers") ?? "", /WWW-Authenticate/i);
  });

  it("sends CORS headers on the MCP endpoint, the metadata and the token endpoints only, never on the pages a person sees", async () => {
    const preflight = (path, method = "POST") => rawRequest(port, { method: "OPTIONS", path, headers: { origin: "https://evil.example", "access-control-request-method": method } });
    for (const path of ["/mcp", "/token", "/register", "/revoke", "/.well-known/oauth-authorization-server", "/.well-known/oauth-protected-resource/mcp"]) {
      const r = await preflight(path, path.startsWith("/.well-known") ? "GET" : "POST");
      assert.equal(r.status, 204, path);
      assert.equal(r.headers["access-control-allow-origin"], "*", path);
    }
    for (const [path, method] of [["/authorize", "GET"], ["/consent", "POST"], ["/callback", "GET"], ["/health", "GET"]]) {
      const r = await preflight(path, method);
      assert.equal(r.headers["access-control-allow-origin"], undefined, `no CORS on the preflight of ${path}`);
      const real = await rawRequest(port, { method, path, headers: { origin: "https://evil.example" } });
      assert.equal(real.headers["access-control-allow-origin"], undefined, `no CORS on ${method} ${path}`);
      assert.equal(real.headers["x-powered-by"], undefined, `no X-Powered-By on ${path}`);
    }
  });

  it("answers 400, not 500, to a body that is not valid JSON, and keeps serving", async () => {
    const token = await freshUser("alice");
    for (const [path, headers] of [["/mcp", { authorization: `Bearer ${token}`, accept: "application/json, text/event-stream" }], ["/mcp", {}], ["/register", {}], ["/token", {}]]) {
      const r = await fetch(`http://localhost:${port}${path}`, { method: "POST", headers: { "content-type": "application/json", ...headers }, body: '{"jsonrpc": "2.0", "method": initialize' });
      const text = await r.text();
      assert.equal(r.status, 400, `${path} ${headers.authorization ? "with" : "without"} a token`);
      assert.match(r.headers.get("content-type") ?? "", /json/, `${path} answers JSON, not an HTML error page`);
      assert.doesNotMatch(text, /node_modules|at \w+ \(/, "no stack trace in the answer");
    }
    // A parse error quotes part of the body, which on /token can be a refresh token, so it must never reach the log.
    const secret = `refresh-${"s".repeat(24)}`;
    await fetch(`http://localhost:${port}/token`, { method: "POST", headers: { "content-type": "application/json" }, body: `{"refresh_token": "${secret}", oops` });
    await sleep(100);
    assert.ok(!server.log().includes(secret), "the body of a broken request is not logged");
    assert.equal(await pingStatus(token, await openSession(token)), 200, "the server still works");
    assert.deepEqual(cloud.seen.foRequests, []);
  });

  // ------------------------------------------------------------ abuse limits

  it("answers 429 with Retry-After once an address used up a sign in endpoint's requests for the minute, and other addresses go on", async () => {
    const client = await registerClient(`http://localhost:${port}`);
    const ip = randomIp();
    const from = (address) => ({ "x-forwarded-for": address });
    const form = { "content-type": "application/x-www-form-urlencoded" };
    // Requests that fail still count: a flood of bad requests is what the limits are for.
    const endpoints = [
      ["GET /authorize", 30, (h) => fetch(authorizeUrl(client, { response_type: "token" }), { redirect: "manual", headers: h }), 302],
      ["POST /consent", 30, (h) => fetch(`http://localhost:${port}/consent`, { method: "POST", headers: { ...form, origin: `http://localhost:${port}`, ...h }, body: "request=x&csrf=y&action=approve" }), 400],
      ["GET /callback", 30, (h) => fetch(`http://localhost:${port}/callback?state=x&code=y`, { headers: h }), 400],
      ["POST /register", 60, (h) => fetch(`http://localhost:${port}/register`, { method: "POST", headers: { "content-type": "application/json", ...h }, body: "{}" }), 400],
      ["POST /token", 300, (h) => fetch(`http://localhost:${port}/token`, { method: "POST", headers: { ...form, ...h }, body: "grant_type=password" }), 400],
      ["POST /revoke", 300, (h) => fetch(`http://localhost:${port}/revoke`, { method: "POST", headers: { ...form, ...h }, body: "token=x" }), 200],
    ];
    for (const [name, limit, send, normal] of endpoints) {
      const answers = await inBatches(limit, 30, () => send(from(ip)));
      assert.deepEqual([...new Set(answers.map((r) => r.status))], [normal], `${name}: the first ${limit} requests are answered`);
      const over = await send(from(ip));
      assert.equal(over.status, 429, name);
      const wait = Number(over.headers.get("retry-after"));
      assert.ok(wait >= 1 && wait <= 60, `${name}: Retry-After ${over.headers.get("retry-after")}`);
      if (name.startsWith("POST /re") || name === "POST /token") assert.equal((await over.json()).error, "temporarily_unavailable", name);
      else await assertPage(over, 429, /Try again in \d+ seconds/);
      const other = await send(from(randomIp()));
      await other.text();
      assert.equal(other.status, normal, `${name}: another address is not affected`);
    }
  });

  it("keeps the limiter's memory bounded: expired windows go first, then the oldest when every key is active", () => {
    const limiter = new RateLimiter(2, 1000, 100);
    const windows = Object.values(limiter).find((v) => v instanceof Map);
    assert.deepEqual([limiter.hit("a", 0), limiter.hit("a", 0), limiter.hit("a", 400)], [undefined, undefined, 1], "the third request waits for the rest of the window");
    for (let i = 0; i < 500; i++) limiter.hit(`key ${i}`, 10);
    assert.equal(windows.size, 100, "500 active keys never take more than 100 windows");
    assert.equal(windows.has("a"), false, "the oldest window made room");
    for (let i = 0; i < 50; i++) limiter.hit(`late ${i}`, 2000);
    assert.equal(windows.size, 50, "expired windows are dropped as new keys arrive");
    assert.equal(limiter.hit("key 499", 2000), undefined, "a key whose window expired starts a new one");
  });

  it("keeps nothing for a sign in until Entra answers: a flood of 2,000 consent pages from 100 addresses leaves new sign ins working", async () => {
    const client = await registerClient(`http://localhost:${port}`);
    const first = makeBrowser({ ip: randomIp() });
    const firstForm = consentForm(await assertPage(await first.fetch(authorizeUrl(client)), 200));
    // One address gets as many consent pages as the rate limit allows, there is no count of sign ins in progress.
    const office = makeBrowser({ ip: randomIp() });
    for (let i = 0; i < 30; i++) consentForm(await assertPage(await office.fetch(authorizeUrl(client)), 200));
    const addresses = Array.from({ length: 100 }, () => randomIp());
    const answers = await inBatches(2000, 50, (i) => fetch(authorizeUrl(client), { headers: { "x-forwarded-for": addresses[i % 100] } }));
    assert.deepEqual([...new Set(answers.map((r) => r.status))], [200]);

    // A new user signs in all the way, and the page from before the flood still works.
    for (const [browser, form] of [[makeBrowser(), undefined], [first, firstForm]]) {
      const toEntra = form ? await postConsent(browser, `http://localhost:${port}`, form) : await authorizeInBrowser(browser, authorizeUrl(client));
      assert.equal(toEntra.status, 303);
      const toClient = await browser.fetch(cloud.authorize(new URL(toEntra.headers.get("location")).searchParams, "alice"));
      assert.ok(new URL(toClient.headers.get("location")).searchParams.get("code"), "the sign in gets its code");
    }
  });

  it("answers 429 to a signed in user after 600 MCP requests in a minute, from any address, and other users go on", async () => {
    const token = await freshUser("alice");
    const send = (t, ip = randomIp()) => mcpPost(serverUrl, t, TOOLS_LIST, undefined, { "x-forwarded-for": ip });
    const answers = await inBatches(600, 50, () => send(token));
    assert.deepEqual([...new Set(answers.map((r) => r.status))], [400], "requests without a session, answered and counted");
    for (const ip of [randomIp(), randomIp()]) {
      const over = await send(token, ip);
      assert.equal(over.status, 429, "the limit is per user, not per address");
      assert.ok(Number(over.headers.get("retry-after")) >= 1);
      const body = await over.json();
      assert.equal(body.jsonrpc, "2.0");
      assert.match(body.error.message, /Too many requests for this user/);
    }
    const other = await send(await freshUser("bob"));
    await other.text();
    assert.equal(other.status, 400, "another user is not affected");
  });

  // ------------------------------------------------------------ listen address and refused configuration

  it("listens on 127.0.0.1 only when the public URL is on localhost, and on MCP_HOST when it is set", async () => {
    assert.match(server.log(), new RegExp(`listening on 127\\.0\\.0\\.1:${port},`));
    const v6 = await new Promise((resolve) => {
      const socket = connect({ host: "::1", port });
      socket.on("connect", () => resolve(socket.destroy() && "connected"));
      socket.on("error", (error) => resolve(error.code));
    });
    assert.notEqual(v6, "connected", "nothing answers on the IPv6 loopback address");

    const pinned = await startServer({
      cloud, certFile: cert.certFile,
      env: { MCP_PUBLIC_URL: "https://mcp.example.com/mcp", MCP_ALLOWED_HOSTS: "localhost", MCP_HOST: "127.0.0.1", FO_INSECURE_TLS: "0", FO_CA_FILE: cert.certFile },
    });
    try {
      assert.match(pinned.log(), new RegExp(`listening on 127\\.0\\.0\\.1:${pinned.port},`));
    } finally {
      await pinned.stop();
    }
  });

  it("starts a test's server on another port when the one picked for it was taken meanwhile, since freePort reserves nothing", async () => {
    // Between the pick and the child's bind a server of another test file can take the port. This listener stands in for
    // it and answers /health with 200 like that server would, so the answer alone must not pass for the child's own.
    const taken = createHttpServer((req, res) => res.writeHead(200, { "content-type": "application/json" }).end('{"status":"ok"}'));
    const takenPort = await listenOn(taken);
    try {
      const picks = [takenPort];
      const moved = await startServer({ cloud, certFile: cert.certFile, pickPort: async () => picks.shift() ?? freePort() });
      try {
        assert.notEqual(moved.port, takenPort);
        assert.match(moved.log(), new RegExp(`EADDRINUSE[^\\n]*:${takenPort}\\b[\\s\\S]*fo-mcp could not bind port ${takenPort}, starting again on another one`));
        const health = await fetch(`http://localhost:${moved.port}/health`);
        await health.text();
        assert.equal(health.status, 200);
      } finally {
        await moved.stop();
      }
      // A port the caller chose is in its public URL, so it is not replaced.
      await assert.rejects(startServer({ port: takenPort, cloud, certFile: cert.certFile }), /^Error: fo-mcp did not start:[\s\S]*EADDRINUSE/);
    } finally {
      await new Promise((resolve) => taken.close(resolve));
    }
  });

  it("refuses to start with an http public URL off localhost, FO_INSECURE_TLS for a public server and other unsafe settings", async () => {
    const https = "https://mcp.example.com/mcp";
    const cases = [
      [{ MCP_PUBLIC_URL: "http://mcp.example.com/mcp" }, "MCP_PUBLIC_URL must start with https:// unless its host is localhost, got 'http://mcp.example.com/mcp'"],
      [{ MCP_PUBLIC_URL: "not a url" }, "MCP_PUBLIC_URL must be an absolute URL such as https://mcp.example.com/mcp, got 'not a url'"],
      [{ MCP_PUBLIC_URL: "ftp://localhost/mcp" }, "MCP_PUBLIC_URL must start with https://, got 'ftp://localhost/mcp'"],
      [{ MCP_PUBLIC_URL: https }, "FO_INSECURE_TLS=1 is only allowed while MCP_PUBLIC_URL is on localhost. Set FO_CA_FILE to the F&O server certificate instead."],
      [{ FO_TENANT_ID: "contoso.onmicrosoft.com" }, "FO_TENANT_ID must be the directory (tenant) ID, a GUID, got 'contoso.onmicrosoft.com'"],
      [{ MCP_STATE_KEY: "too short" }, "MCP_STATE_KEY must be at least 32 characters"],
      [{ MCP_ALLOWED_CLIENT_APPS: "my-app" }, "MCP_ALLOWED_CLIENT_APPS must be app (client) IDs separated by commas, or none, got 'my-app'"],
      // The MCP SDK refuses an http issuer on [::1], so the server says what to use instead of failing on that.
      [{ MCP_PUBLIC_URL: "http://[::1]:3000/mcp" }, "MCP_PUBLIC_URL must use localhost or 127.0.0.1 for plain http, the MCP SDK refuses http on [::1], got 'http://[::1]:3000/mcp'"],
      [
        { MCP_PUBLIC_URL: https, FO_INSECURE_TLS: "0", FO_CA_FILE: cert.certFile, NODE_TLS_REJECT_UNAUTHORIZED: "0" },
        "NODE_TLS_REJECT_UNAUTHORIZED=0 is only allowed while MCP_PUBLIC_URL is on localhost, it turns off certificate validation for Entra and F&O. Remove it and set FO_CA_FILE to the F&O server certificate.",
      ],
      [{ MCP_TRUST_PROXY: "yes" }, "MCP_TRUST_PROXY must be the number of proxies in front of the server that append to X-Forwarded-For, 0 to 10, got 'yes'"],
      [{ MCP_TRUST_PROXY: "11" }, "MCP_TRUST_PROXY must be the number of proxies in front of the server that append to X-Forwarded-For, 0 to 10, got '11'"],
      // Once silently 3000, which the default public URL then followed.
      ...["34567x", "0", "70000", "0x50"].map((value) => [{ MCP_PORT: value }, `MCP_PORT must be a whole number from 1 to 65535, got '${value}'`]),
      // What the image does with an empty MCP_PUBLIC_URL: the localhost profile, served on every interface.
      [
        { MCP_HOST: "0.0.0.0" },
        "MCP_PUBLIC_URL must be set while MCP_HOST=0.0.0.0 makes the server listen beyond this machine, for example https://mcp.example.com/mcp. " +
          "For a local test set MCP_PUBLIC_URL=http://localhost:1/mcp and publish the port on 127.0.0.1 only.",
      ],
    ];
    const results = await Promise.all(cases.map(([env]) => runRefused(serverEnv(cloud, cert.certFile, { MCP_PORT: "1", ...env }))));
    cases.forEach(([env, message], i) => {
      const { code, stdout, stderr } = results[i];
      const label = JSON.stringify(env);
      assert.equal(code, 1, `${label} must exit with code 1, stderr: ${stderr}`);
      assert.ok(stderr.includes(`fo-mcp: ${message}`), `${label} must say "${message}", stderr was: ${stderr}`);
      assert.doesNotMatch(stderr, /\n\s+at /, `${label} must not print a stack trace`);
      assert.equal(stdout, "");
    });
    assert.deepEqual(cloud.seen.tokenGrants, [], "a server with unsafe settings never asks Entra for a token");
  });

  it("warns at start about settings that work but that README calls unsafe for what the server is set up as", async () => {
    const warnings = {
      everyInterface: /fo-mcp: MCP_HOST=0\.0\.0\.0 makes the server listen beyond this machine while MCP_PUBLIC_URL is on localhost, .*docker run -p 127\.0\.0\.1:/,
      ownApp: /fo-mcp: MCP_ALLOWED_CLIENT_APPS lists FO_CLIENT_ID, the server's own app\. .*device code phishing/,
      noRole: /fo-mcp: writes are enabled for every user who can sign in\. Set MCP_WRITE_ROLE to the app role a user needs for create_record and update_record\./,
    };
    const hosted = { MCP_PUBLIC_URL: "https://mcp.example.com/mcp", MCP_ALLOWED_HOSTS: "localhost", MCP_HOST: "127.0.0.1", FO_INSECURE_TLS: "0", FO_CA_FILE: cert.certFile };
    const startWith = async (env) => {
      const otherPort = await freePort();
      const other = await startServer({ port: otherPort, cloud, certFile: cert.certFile, env: { MCP_PUBLIC_URL: `http://localhost:${otherPort}/mcp`, ...env } });
      await other.stop();
      return other.log();
    };
    // An explicit localhost URL on every interface starts, as a local docker run needs it, but says what that exposes.
    const exposed = await startWith({ MCP_HOST: "0.0.0.0" });
    assert.match(exposed, warnings.everyInterface);
    // README: never list the server's own app on a hosted server, and set MCP_WRITE_ROLE when writes are on.
    const unsafe = await startWith({ ...hosted, MCP_ALLOWED_CLIENT_APPS: clientId, FO_ALLOW_WRITES: "1", FO_WRITE_ENTITIES: "CustomerGroups" });
    assert.match(unsafe, warnings.ownApp);
    assert.match(unsafe, warnings.noRole);
    assert.doesNotMatch(unsafe, warnings.everyInterface);
    const safe = await startWith({ ...hosted, FO_ALLOW_WRITES: "1", FO_WRITE_ENTITIES: "CustomerGroups", MCP_WRITE_ROLE: "FO.Write" });
    for (const pattern of Object.values(warnings)) {
      assert.doesNotMatch(safe, pattern);
      assert.doesNotMatch(server.log(), pattern, "on localhost the server's own app is the default and nobody else reaches it");
    }
  });

  it("sends no HSTS on an https public URL on localhost, which would move every local port to https", async () => {
    for (const host of ["localhost", "127.0.0.1"]) {
      const localPort = await freePort();
      const local = await startServer({ port: localPort, cloud, certFile: cert.certFile, env: { MCP_PUBLIC_URL: `https://${host}:${localPort}/mcp` } });
      try {
        for (const path of ["/health", "/.well-known/oauth-authorization-server"]) {
          const r = await rawRequest(localPort, { path, headers: { host: `${host}:${localPort}` } });
          assert.equal(r.status, 200, `${host}${path}: ${r.text}`);
          assert.equal(r.headers["strict-transport-security"], undefined, `${host}${path}`);
        }
      } finally {
        await local.stop();
      }
    }
  });

  it("answers a request body over 100 KB with 413 and says so, instead of an internal error the model would repeat", async () => {
    const token = await freshUser("alice");
    const id = await openSession(token);
    const call = { jsonrpc: "2.0", id: 4, method: "tools/call", params: { name: "query_entity", arguments: { entity: "CustomersV3", filter: `OrganizationName eq '${"x".repeat(120_000)}'` } } };
    const r = await mcpPost(serverUrl, token, call, id);
    assert.equal(r.status, 413);
    assert.deepEqual(await r.json(), {
      jsonrpc: "2.0",
      error: { code: -32600, message: "The request is over the 100 KB this server accepts in one call. Shorten the long text values in it." },
      id: null,
    });
    const form = await fetch(`http://localhost:${port}/token`, {
      method: "POST", headers: { "content-type": "application/x-www-form-urlencoded", "x-forwarded-for": randomIp() }, body: `grant_type=refresh_token&refresh_token=${"r".repeat(120_000)}`,
    });
    assert.equal(form.status, 413);
    assert.deepEqual(await form.json(), { error: "invalid_request", error_description: "The request is over the 100 KB this server accepts in one call. Shorten the long text values in it." });
    assert.equal(await pingStatus(token, id), 200, "the session goes on");
    assert.deepEqual(cloud.seen.foRequests, []);
  });

  it("keeps a developer's .env out of every server under test, MCP_TRUST_PROXY and NODE_TLS_REJECT_UNAUTHORIZED included", async () => {
    const env = serverEnv(cloud, cert.certFile);
    assert.deepEqual(serverVariables().filter((name) => env[name] === undefined), [], "every FO_ and MCP_ variable the built server mentions is set");
    assert.ok(serverVariables().includes("MCP_TRUST_PROXY"), serverVariables().join(", "));
    // A copy of the server next to a .env that follows README's advice for a server with nothing in front of it. Read by
    // the tests' servers, it took every request for 127.0.0.1 and used up the limits per address.
    const dir = mkdtempSync(join(tmpdir(), "fo-mcp-dotenv-"));
    try {
      copyBuiltServer(dir);
      writeFileSync(join(dir, ".env"), "MCP_TRUST_PROXY=0\nNODE_TLS_REJECT_UNAUTHORIZED=0\nFO_ALLOW_WRITES=1\n");
      const copy = await startServer({ cloud, certFile: cert.certFile, script: join(dir, "dist", "http.js") });
      try {
        assert.match(await logLine(copy, "listening on"), /, read-only, .*, client addresses from X-Forwarded-For behind 1 proxy$/);
        assert.doesNotMatch(copy.log(), /NODE_TLS_REJECT_UNAUTHORIZED/);
      } finally {
        await copy.stop();
      }
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("warns at start that NODE_TLS_REJECT_UNAUTHORIZED=0 turns off every certificate check, where localhost allows it", async () => {
    const warned = await startServer({ cloud, certFile: cert.certFile, env: { NODE_TLS_REJECT_UNAUTHORIZED: "0" } });
    try {
      assert.match(warned.log(), /fo-mcp: NODE_TLS_REJECT_UNAUTHORIZED=0 turns off certificate validation for every connection, Entra included\./);
    } finally {
      await warned.stop();
    }
    assert.doesNotMatch(server.log(), /NODE_TLS_REJECT_UNAUTHORIZED/);
  });

  // ------------------------------------------------------------ keep-alive and clock skew

  it("keeps an idle connection open for more than the 5 s Node defaults to, so the ingress can send the next tool call on it", async () => {
    // The ingress pools its connections to the replica and ignores the Keep-Alive header, so a connection the server
    // closes as idle can have the next request on its way, which the client sees as a reset.
    const agent = new Agent({ keepAlive: true, maxSockets: 1 });
    const get = () =>
      new Promise((resolve, reject) => {
        const req = request({ host: "localhost", port, path: "/health", agent }, (res) => {
          res.resume();
          res.on("end", () => resolve({ status: res.statusCode, headers: res.headers, reused: req.reusedSocket }));
        });
        req.on("error", reject);
        req.end();
      });
    try {
      const first = await get();
      assert.equal(first.status, 200);
      assert.equal(first.headers["keep-alive"], "timeout=65", "the answer says how long the connection stays open");
      // A user who thinks for a few seconds between two tool calls, the common case.
      await sleep(5500);
      const second = await get();
      assert.equal(second.status, 200);
      assert.equal(second.reused, true, "the second request goes over the same connection");
    } finally {
      agent.destroy();
    }
  });

  it("accepts a direct Entra token whose nbf is a little ahead of its own clock, and still refuses one far ahead or expired", async () => {
    const now = Math.floor(Date.now() / 1000);
    const oid = `oid-alice-${random()}`;
    const challenge = async (overrides) => {
      const r = await mcpPost(serverUrl, await cloud.userToken("alice", audience, { oid, ...overrides }), INITIALIZE);
      await r.text();
      return [r.status, r.headers.get("www-authenticate") ?? ""];
    };
    // Entra sets nbf to its own time, so a server a minute behind must still take the token.
    await openSession(await cloud.userToken("alice", audience, { oid, nbf: now + 60 }));
    const [ahead, aheadHeader] = await challenge({ nbf: now + 600 });
    assert.equal(ahead, 401, "ten minutes ahead is not clock skew");
    assert.match(aheadHeader, /Token rejected: 'nbf' claim timestamp check failed/);
    // The tolerance does not extend the life of a token: an expired one stays refused, however little it is past.
    const [expired, expiredHeader] = await challenge({ exp: now - 60 });
    assert.equal(expired, 401);
    assert.match(expiredHeader, /Token has expired/);
    assert.deepEqual(cloud.seen.foRequests, []);
  });

  // ------------------------------------------------------------ sessions that end with a write in flight

  it("ends a session whose user lost the write role only once the update it sent to F&O has its answer, so the client learns the outcome", async () => {
    const writing = await startServer({ cloud, certFile: cert.certFile, env: WRITE_ROLE_ENV });
    let held;
    try {
      const oid = `oid-alice-${random()}`;
      const token = await cloud.userToken("alice", audience, { oid });
      const id = await openSession(token, writing.url);
      held = await holdUpdate(writing.url, token, id, "Role lost");
      // Alice's next token lacks the role. The request that brings it is answered 404 and the session ends, but the
      // update F&O is applying must not be aborted with it: its answer would never reach the client, which would see an
      // empty 200 and repeat the write.
      const withoutRole = await cloud.userToken("alice", audience, { oid, roles: undefined });
      const lost = await mcpPost(writing.url, withoutRole, TOOLS_LIST, id);
      await lost.text();
      assert.equal(lost.status, 404, "the session with the write tools ends once the user's token lacks the role");
      assert.equal(await pingStatus(token, id, writing.url), 404, "and takes no further request, with the old token either");
      // Time for a close of the transport to cut the update off, which it must not. Then F&O answers.
      await sleep(200);
      held.release();
      const reply = await Promise.race([held.answer.then(rpcBody), sleep(2000).then(() => undefined)]);
      assert.ok(reply, "the update answers once F&O did");
      assert.ok(!reply.result.isError, reply.result.content[0].text);
      const updated = JSON.parse(reply.result.content[0].text);
      assert.deepEqual([updated.before, updated.after], [{ Description: "Wholesale" }, { Description: "Role lost" }]);
      const audit = updateAudit(writing);
      assert.deepEqual([audit?.ok, audit?.sent, audit?.outcome], [true, true, undefined], JSON.stringify(audit));
      assert.equal(cloud.seen.foRequests.filter((r) => r.method === "PATCH").length, 1, "the write went out once");
    } finally {
      held?.release();
      await writing.stop();
    }
  });

  it("makes room for a user's 11th session by ending the least recently used one only once the update it sent has its answer", async () => {
    const writing = await startServer({ cloud, certFile: cert.certFile, env: WRITE_ROLE_ENV });
    let held;
    try {
      const token = await cloud.userToken("alice", audience, { oid: `oid-alice-${random()}` });
      const first = await openSession(token, writing.url);
      held = await holdUpdate(writing.url, token, first, "Evicted");
      await sleep(5);
      // Ten more sessions: the 11th initialize evicts the first one, the least recently used, while its update waits for F&O.
      const others = [];
      for (let i = 0; i < 10; i++) others.push(await openSession(token, writing.url));
      assert.equal(await pingStatus(token, first, writing.url), 404, "the first session is gone");
      assert.equal(await pingStatus(token, others[0], writing.url), 200);
      held.release();
      const reply = await Promise.race([held.answer.then(rpcBody), sleep(2000).then(() => undefined)]);
      assert.ok(reply, "the update answers once F&O did");
      assert.ok(!reply.result.isError, reply.result.content[0].text);
      assert.deepEqual(JSON.parse(reply.result.content[0].text).after, { Description: "Evicted" });
      assert.deepEqual([updateAudit(writing)?.ok, updateAudit(writing)?.outcome], [true, undefined]);
    } finally {
      held?.release();
      await writing.stop();
    }
  });

  // ------------------------------------------------------------ shutdown

  it("lets a write already sent get F&O's answer on SIGTERM, so its outcome is known, writes its audit line and exits", { skip: noSignals() }, async () => {
    const doomed = await startServer({ cloud, certFile: cert.certFile, env: { FO_ALLOW_WRITES: "1", FO_WRITE_ENTITIES: "CustomerGroups" } });
    let held;
    try {
      const token = await freshUser("alice");
      const id = await openSession(token, doomed.url);
      // F&O applies the change and answers a second after the signal, well within the grace a sent write gets.
      held = await holdUpdate(doomed.url, token, id, "Cut short");
      doomed.child.kill("SIGTERM");
      await sleep(1000);
      assert.equal(doomed.child.exitCode, null, "the server waits for the write it sent");
      held.release();
      const reply = await Promise.race([held.answer.then(rpcBody), sleep(2000).then(() => undefined)]);
      assert.ok(reply, "the call answers once F&O did");
      const { result } = reply;
      assert.ok(!result.isError, result.content[0].text);
      const updated = JSON.parse(result.content[0].text);
      assert.deepEqual(updated.before, { Description: "Wholesale" });
      assert.equal(updated.note, "The update went through, but the tool call was stopped before the record could be read again.");
      const outcome = await Promise.race([doomed.exited, sleep(2000).then(() => "still running")]);
      assert.equal(outcome, 0, "the process exits cleanly once the answer is out");
      const audit = updateAudit(doomed);
      assert.ok(audit, `the call has its audit line:\n${doomed.log()}`);
      assert.deepEqual([audit.ok, audit.sent, audit.outcome], [true, true, undefined]);
    } finally {
      held?.release();
      if (doomed.child.exitCode === null && doomed.child.signalCode === null) doomed.child.kill("SIGKILL");
    }
  });

  it("ends the process within 2 s on SIGTERM, even with an open session stream", { skip: noSignals() }, async () => {
    const doomed = await startServer({ cloud, certFile: cert.certFile });
    const token = await freshUser("alice");
    const id = await openSession(token, doomed.url);
    const stream = new AbortController();
    const sse = await fetch(doomed.url, { headers: { authorization: `Bearer ${token}`, accept: "text/event-stream", "mcp-session-id": id }, signal: stream.signal });
    assert.equal(sse.status, 200, "an SSE stream is open while the signal arrives");
    try {
      const started = Date.now();
      doomed.child.kill("SIGTERM");
      const outcome = await Promise.race([doomed.exited, sleep(2000).then(() => "still running")]);
      assert.equal(outcome, 0, `the server must exit cleanly within 2 s, got ${outcome} after ${Date.now() - started} ms`);
    } finally {
      stream.abort();
      if (doomed.child.exitCode === null && doomed.child.signalCode === null) doomed.child.kill("SIGKILL");
    }
  });
});
