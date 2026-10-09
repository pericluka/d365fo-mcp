// Regressions found after the full review: work shared between tool calls, a revoked sign in coming back through a
// refresh that was already waiting on Entra, a shutdown that cut tool calls in flight, and tool arguments with a wrong
// name that were dropped without a word. The second part, after the third and fourth review, runs the F&O client and
// the tools in this process: a shutdown that stops calls at once but lets a write already sent get its answer, calls
// that end as stopped instead of as a success, the memory held by F&O answers and caches, writes that start too late
// to be answered and the audit of a write that never went out. After the fifth review: the local server's shutdown on a
// signal, a refresh of the entity list that fails, a name that is not on the list and the bound of the shared caches.
// Runs against the fake cloud.
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import assert from "node:assert/strict";
import { after, before, beforeEach, describe, it } from "node:test";
import { FoClient, FoShared, loadConfig } from "../dist/fo.js";
import { createFoServer } from "../dist/server.js";
import {
  callTool, callToolRaw, clientId, clientSecret, connectWithSignIn, DATA_ENTITIES, freePort, makeCert, makeProvider, mcpPost, INITIALIZE, NO_OPENSSL, noSignals,
  PUBLIC_ENTITIES, random, refreshAt, sleep, startFakeCloud, startServer, startStdio, SUITE_TIMEOUT, tenantId,
} from "./support.mjs";

async function until(condition, what) {
  const deadline = Date.now() + 5000;
  while (!condition()) {
    if (Date.now() > deadline) assert.fail(`timed out waiting for ${what}`);
    await sleep(10);
  }
}

describe("regressions after the full review", { timeout: SUITE_TIMEOUT, skip: NO_OPENSSL }, () => {
  let cert, cloud;

  before(async () => {
    cert = makeCert();
    cloud = await startFakeCloud(cert.dir);
  });

  after(async () => {
    await cloud?.close();
    cert?.remove();
  });

  beforeEach(() => cloud.reset());

  it("does not fail a call that shares the entity list load with another call that gets cancelled", async () => {
    const server = await startStdio({ cloud, certFile: cert.certFile }); // cold caches
    try {
      cloud.faults.metadataDelayMs = 800;
      const cancel = new AbortController();
      const first = callToolRaw(server.client, "search_entities", { query: "customer" }, { signal: cancel.signal }).catch((error) => ({ cancelled: error }));
      await sleep(100);
      const second = callToolRaw(server.client, "search_entities", { query: "sales order" });
      await sleep(100);
      cancel.abort();
      assert.ok((await first).cancelled, "the first call ends as cancelled");
      const result = await second;
      assert.equal(result.isError, false, `the second call must not fail because the first was cancelled: ${result.text}`);
      assert.match(result.text, /SalesOrderHeadersV2/);
      const loads = cloud.seen.foRequests.filter((r) => r.path.startsWith("/Metadata/DataEntities"));
      assert.equal(loads.length, 1, "both calls share one load of the entity list");
    } finally {
      await server.close();
    }
  });

  it("keeps a revoked sign in revoked when a refresh of it was already waiting on Entra", async () => {
    const server = await startServer({ cloud, certFile: cert.certFile });
    const { port } = server;
    try {
      const provider = makeProvider(cloud, "alice");
      const client = await connectWithSignIn(server.url, provider);
      await client.close();
      const stolen = provider._tokens.refresh_token;
      // The thief uses the stolen refresh token first and gets the next pair.
      const thief = await (await refreshAt(port, provider, stolen)).json();
      await sleep(5200); // past the grace period for parallel requests
      cloud.faults.refreshDelayMs = 1500;
      const thiefRefresh = refreshAt(port, provider, thief.refresh_token); // waits on Entra
      await sleep(200);
      // The owner presents the old token, which reveals the theft and revokes the sign in.
      const owner = await refreshAt(port, provider, stolen);
      assert.equal(owner.status, 400);
      const late = await thiefRefresh;
      assert.equal(late.status, 400, "the refresh that was waiting must not bring the revoked sign in back");
      assert.equal((await late.json()).error, "invalid_grant");
      assert.equal((await mcpPost(server.url, thief.access_token, INITIALIZE)).status, 401, "the thief's access token is dead");
    } finally {
      cloud.faults.refreshDelayMs = 0;
      await server.stop();
    }
  });

  it("survives a call that arrives already cancelled while the shared load it started fails", async () => {
    const server = await startServer({ cloud, certFile: cert.certFile });
    const { port } = server;
    try {
      // Eve signs in to Entra but has no F&O user, so the entity list load she starts fails with 403.
      const token = await cloud.userToken("eve", `api://${clientId}`);
      const init = await mcpPost(server.url, token, INITIALIZE);
      const session = init.headers.get("mcp-session-id");
      await init.text();
      await (await mcpPost(server.url, token, { jsonrpc: "2.0", method: "notifications/initialized" }, session)).text();
      // One batch with the call and its cancel: the SDK aborts the signal before the tool handler runs.
      const batch = [
        { jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "search_entities", arguments: { query: "customer" } } },
        { jsonrpc: "2.0", method: "notifications/cancelled", params: { requestId: 2, reason: "test" } },
      ];
      // A cancelled request gets no answer (MCP spec), so the batch response never completes. Give up on it after a moment.
      const giveUp = new AbortController();
      const pending = fetch(server.url, {
        method: "POST",
        headers: { "content-type": "application/json", accept: "application/json, text/event-stream", authorization: `Bearer ${token}`, "mcp-session-id": session },
        body: JSON.stringify(batch),
        signal: giveUp.signal,
      }).then((r) => r.text()).catch(() => {});
      await sleep(800);
      giveUp.abort();
      await pending;
      assert.equal(server.child.exitCode, null, `the server must keep running:\n${server.log()}`);
      assert.equal((await fetch(`http://localhost:${port}/health`)).status, 200);
      // The safety net in http.ts would hide a crash, so check the cause directly: the cancelled call starts no load
      // and nothing ends up as an unhandled rejection.
      assert.equal(cloud.seen.foRequests.filter((r) => r.path.startsWith("/Metadata/DataEntities")).length, 0, "a cancelled call starts no shared load");
      assert.doesNotMatch(server.log(), /unhandled rejection/);
    } finally {
      await server.stop();
    }
  });

  it("refuses misnamed arguments: orderBy and $filter were once dropped and the call read every row as a success", async () => {
    const server = await startStdio({ cloud, certFile: cert.certFile });
    try {
      const { text, isError } = await callToolRaw(server.client, "query_entity", { entity: "CustomersV3", orderBy: "CustomerAccount", $filter: "CustomerGroupId eq '20'" });
      assert.equal(isError, true, text);
      assert.equal(
        text,
        "MCP error -32602: Input validation error: Invalid arguments for tool query_entity: Unknown argument orderBy, $filter. " +
          "Valid arguments: entity, filter, select, orderby, expand, top, skip, count, company, crossCompany"
      );
      assert.deepEqual(cloud.seen.foRequests, [], "nothing is read with the filter missing");
    } finally {
      await server.close();
    }
  });

  it("answers a tool call in flight at once on SIGTERM that the server is restarting, then exits", { skip: noSignals() }, async () => {
    const server = await startServer({ cloud, certFile: cert.certFile });
    const client = await connectWithSignIn(server.url, makeProvider(cloud, "alice"));
    try {
      await callToolRaw(client, "environment_info"); // warm the caches so only the data request is slow
      cloud.faults.dataDelayMs = 1500;
      const call = callToolRaw(client, "query_entity", { entity: "CustomersV3", select: "CustomerAccount" });
      await sleep(300);
      const started = Date.now();
      server.child.kill("SIGTERM");
      // A call may take longer than the replica has left, so it does not wait for F&O but gets an answer it can act on.
      const result = await call;
      assert.ok(Date.now() - started < 1000, `the call answers at once, not when F&O does, after ${Date.now() - started} ms`);
      assert.deepEqual(result, { isError: true, text: "The server is restarting, so the tool call was stopped. Call the tool again in a moment." });
      const outcome = await Promise.race([server.exited, sleep(3000).then(() => "still running")]);
      assert.equal(outcome, 0, "the process exits cleanly once the call is answered");
      assert.ok(Date.now() - started < 3000);
    } finally {
      cloud.faults.dataDelayMs = 0;
      await client.close().catch(() => {});
      if (server.child.exitCode === null && server.child.signalCode === null) server.child.kill("SIGKILL");
    }
  });

  it("lets a create already sent by the local server finish on SIGTERM, with its audit line, stops a read at once and exits once both answered", { skip: noSignals() }, async () => {
    const server = await startStdio({ cloud, certFile: cert.certFile, env: { FO_ALLOW_WRITES: "1" } });
    try {
      await callTool(server.client, "describe_entity", { entity: "CustomerGroups", fields: "x" }); // the metadata is cached now
      cloud.reset();
      cloud.faults.dataDelayMs = 1000; // within the grace of the local server, which is shorter than the client's SIGKILL
      const create = callToolRaw(server.client, "create_record", { entity: "CustomerGroups", data: { CustomerGroupId: "88" } });
      const read = callToolRaw(server.client, "query_entity", { entity: "CustomerGroups", select: "CustomerGroupId" });
      await until(() => ["POST", "GET"].every((method) => cloud.seen.foRequests.some((r) => r.method === method && r.path.startsWith("/data/CustomerGroups"))), "the POST and the read to reach F&O");
      const started = Date.now();
      server.child.kill("SIGTERM");
      // Without a handler the process ends here, two seconds before the MCP client would send SIGKILL, and the record F&O
      // creates meanwhile is answered to nobody and audited nowhere.
      assert.deepEqual(await read, { isError: true, text: "The server is restarting, so the tool call was stopped. Call the tool again in a moment." });
      assert.ok(Date.now() - started < 1000, `a read stops at once, not when F&O answers, after ${Date.now() - started} ms`);
      const created = await create;
      assert.equal(created.isError, false, created.text);
      assert.equal(JSON.parse(created.text).key.CustomerGroupId, "88");
      assert.ok(cloud.tables.CustomerGroups.some((g) => g.CustomerGroupId === "88"));
      const outcome = await Promise.race([server.exited, sleep(3000).then(() => "still running")]);
      assert.equal(outcome, 0, `the process exits by itself once the answers are out:\n${server.log()}`);
      const events = server.log().split("\n").filter((line) => line.startsWith("{")).map((line) => JSON.parse(line));
      const audited = (tool) => events.find((e) => e.tool === tool);
      assert.deepEqual([audited("create_record").ok, audited("create_record").sent, audited("create_record").outcome], [true, true, undefined], "the audit line of the create");
      assert.equal(audited("query_entity").ok, false, "the audit line of the stopped read");
    } finally {
      cloud.faults.dataDelayMs = 0;
      await server.close().catch(() => {});
      if (server.child.exitCode === null && server.child.signalCode === null) server.child.kill("SIGKILL");
    }
  });

  it("never follows a redirect from Entra on the F&O token request, with client credentials or on behalf of a user", async () => {
    const refused = /^Token request to https:\/\/localhost:\d+\/[-0-9a-f]+\/oauth2\/v2\.0\/token was answered with a redirect to localhost:\d+, which is not followed\. Check FO_AUTHORITY\.$/;
    cloud.faults.entraRedirects = ["token"];
    const local = await startStdio({ cloud, certFile: cert.certFile });
    try {
      const { text, isError } = await callToolRaw(local.client, "environment_info");
      assert.equal(isError, true);
      assert.match(text, refused);
    } finally {
      await local.close();
    }
    const server = await startServer({ cloud, certFile: cert.certFile });
    try {
      // A token straight from Entra, so the sign in itself does not need the token endpoint.
      const token = await cloud.userToken("alice", `api://${clientId}`, { oid: `oid-${random()}` });
      const init = await mcpPost(server.url, token, INITIALIZE);
      const session = init.headers.get("mcp-session-id");
      await init.text();
      const call = await mcpPost(server.url, token, { jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "environment_info", arguments: {} } }, session);
      const body = await call.text();
      const message = JSON.parse((body.split("\n").find((l) => l.startsWith("data: ")) ?? `data: ${body}`).slice(6));
      assert.equal(message.result.isError, true);
      assert.match(message.result.content[0].text, refused);
    } finally {
      await server.stop();
    }
    assert.deepEqual(cloud.seen.redirected, [], "neither the client secret nor the user's token went on to the host the redirect named");
  });
});

describe("regressions after the third and fourth review, in process", { timeout: SUITE_TIMEOUT, skip: NO_OPENSSL }, () => {
  let cert, cloud;
  const proxies = ["HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"];
  const saved = {};

  before(async () => {
    cert = makeCert();
    cloud = await startFakeCloud(cert.dir);
    // FoShared reads the proxy variables of this process. The fake cloud on localhost must be reached directly.
    for (const name of proxies) {
      saved[name] = process.env[name];
      delete process.env[name];
    }
  });

  after(async () => {
    for (const name of proxies) if (saved[name] !== undefined) process.env[name] = saved[name];
    await cloud?.close();
    cert?.remove();
  });

  beforeEach(() => cloud.reset());

  /** Dispatchers and caches for the fake environment. This process trusts the fake's certificate through FO_CA_FILE. */
  const sharedFor = (env = {}) =>
    new FoShared(loadConfig({ FO_URL: cloud.foUrl, FO_TENANT_ID: tenantId, FO_CLIENT_ID: clientId, FO_CLIENT_SECRET: clientSecret, FO_COMPANY: "USMF", FO_CA_FILE: cert.certFile, ...env }));
  /** The token the fake F&O takes for the service identity, without asking the fake Entra. */
  const serviceToken = async () => ({ accessToken: "fo-token-for-service", expiresIn: 3600 });

  /** An MCP client connected in memory to createFoServer on shared, with the audit events it reported. */
  async function connect(shared) {
    const fo = new FoClient(shared, serviceToken);
    const events = [];
    const server = createFoServer({ version: "0.0.0-test", shared, resolve: () => fo, audit: (event) => events.push(event) });
    const [clientSide, serverSide] = InMemoryTransport.createLinkedPair();
    await server.connect(serverSide);
    const client = new Client({ name: "in-process", version: "0.0.0" });
    await client.connect(clientSide);
    return { client, events, close: () => client.close() };
  }

  it("stops every tool call at once on shutdown, says the server is restarting and that a write already sent may have been applied", async () => {
    const shared = sharedFor({ FO_ALLOW_WRITES: "1" });
    const session = await connect(shared);
    try {
      await callTool(session.client, "describe_entity", { entity: "CustomerGroups", fields: "x" }); // the metadata is cached now
      cloud.reset();
      cloud.faults.dataDelayMs = 5000;
      const read = callToolRaw(session.client, "query_entity", { entity: "CustomerGroups", select: "CustomerGroupId" });
      const create = callToolRaw(session.client, "create_record", { entity: "CustomerGroups", data: { CustomerGroupId: "88" } });
      await until(() => cloud.seen.foRequests.length === 2, "the read and the POST to reach F&O");
      const started = Date.now();
      shared.shutdown();
      const [stopped, unsure] = await Promise.all([read, create]);
      assert.ok(Date.now() - started < 1000, "the calls answer at once, not when F&O does");
      assert.equal(shared.stopping, true);
      assert.deepEqual(stopped, { isError: true, text: "The server is restarting, so the tool call was stopped. Call the tool again in a moment." });
      assert.deepEqual(unsure, {
        isError: true,
        text: "The server is restarting, so the tool call was stopped. F&O may still have processed the request, so check with query_entity before repeating a create.",
      });
      const event = session.events.find((e) => e.tool === "create_record");
      assert.deepEqual([event.ok, event.outcome, event.sent], [false, "unknown", true]);

      // A call that arrives after the shutdown sends nothing to F&O.
      cloud.reset();
      const late = await callToolRaw(session.client, "query_entity", { entity: "CustomerGroups", select: "CustomerGroupId" });
      assert.equal(late.text, "The server is restarting, so the tool call was stopped. Call the tool again in a moment.");
      assert.deepEqual(cloud.seen.foRequests, []);
    } finally {
      cloud.faults.dataDelayMs = 0;
      await session.close();
    }
  });

  it("queues a call past six of one identity, hands it the next free place, and lets it leave the queue on a cancel, its deadline or a shutdown", async () => {
    const shared = sharedFor({ FO_TIMEOUT_MS: "1000" });
    const fo = new FoClient(shared, serviceToken);
    const enter = (signal) => fo.withBudget(() => shared.enterCall(fo.identity), signal);
    /** A call that must get its place at once, not after waiting for its budget. */
    const atOnce = async (call, what) => {
      const started = Date.now();
      await call;
      assert.ok(Date.now() - started < 300, `${what} got its place after ${Date.now() - started} ms`);
    };
    // Six places taken, as by six tool calls still running.
    for (let i = 0; i < 6; i++) await atOnce(enter(), `call ${i + 1}`);

    const started = Date.now();
    await assert.rejects(enter(), {
      message: "No place for this tool call within the 1 s a tool call may take: 6 other calls of this user ran all the time. Make fewer calls at once.",
    });
    assert.ok(Date.now() - started >= 900, "it waited out its own budget");
    const controller = new AbortController();
    const cancelled = enter(controller.signal);
    await sleep(100);
    controller.abort();
    await assert.rejects(cancelled, { message: "The tool call was cancelled." });
    // Neither of them is still in the queue: a place that is given back goes to the next call, not to one that left.
    shared.leaveCall(fo.identity);
    await atOnce(enter(), "a call after a place was given back");

    // A waiting call takes over the place of a call that ends, so the six stay six.
    const waiting = enter();
    await sleep(100);
    shared.leaveCall(fo.identity);
    await atOnce(waiting, "the waiting call");

    // At most ten wait per identity, the next is refused at once. Another identity is not held up by them.
    const queue = Array.from({ length: 10 }, () => enter());
    for (const call of queue) call.catch(() => {});
    await atOnce(assert.rejects(enter(), { message: "Too many tool calls at once for this user, wait for the running ones." }), "the call past the queue");
    const bob = new FoClient(shared, serviceToken, "bob", "oid-bob");
    await atOnce(bob.withBudget(() => shared.enterCall(bob.identity)), "another identity");
    shared.shutdown();
    for (const call of queue) await assert.rejects(call, { message: "The server is restarting, so the tool call was stopped. Call the tool again in a moment." });
  });

  it("hands each free place to the call that waited longest, and keeps the queue as long as before after many calls left it", async () => {
    const shared = sharedFor({ FO_TIMEOUT_MS: "5000" });
    const fo = new FoClient(shared, serviceToken);
    const enter = (signal) => fo.withBudget(() => shared.enterCall(fo.identity), signal);
    for (let i = 0; i < 6; i++) await enter();
    const started = [];
    const waiting = [];
    for (const n of [1, 2, 3]) {
      waiting.push(enter().then(() => started.push(n)));
      await sleep(10);
    }
    for (const n of [1, 2, 3]) {
      shared.leaveCall(fo.identity);
      await until(() => started.length === n, `waiting call ${n} to start`);
    }
    await Promise.all(waiting);
    assert.deepEqual(started, [1, 2, 3], "in order of arrival");
    shared.shutdown();

    // 120 waits that are cancelled and 20 that run out of time, ten at a time, far more than the queue holds at once.
    const churned = sharedFor({ FO_TIMEOUT_MS: "1000" });
    const other = new FoClient(churned, serviceToken);
    const wait = (signal) => other.withBudget(() => churned.enterCall(other.identity), signal);
    for (let i = 0; i < 6; i++) await wait();
    for (let round = 0; round < 12; round++) {
      const controllers = Array.from({ length: 10 }, () => new AbortController());
      const calls = controllers.map((controller) => wait(controller.signal));
      await sleep(10); // all ten are in the queue now
      for (const controller of controllers) controller.abort();
      // Every rejection gets its handler at once: one waited for in turn could reject first and count as unhandled.
      await Promise.all(calls.map((call) => assert.rejects(call, { message: "The tool call was cancelled." })));
    }
    for (let round = 0; round < 2; round++) {
      const calls = Array.from({ length: 10 }, () => wait());
      await Promise.all(calls.map((call) => assert.rejects(call, { message: /^No place for this tool call within the 1 s/ })));
    }
    // Ten wait again and the eleventh is refused, as at the start. A place given back goes to a call still waiting.
    const queue = Array.from({ length: 10 }, () => wait());
    for (const call of queue) call.catch(() => {});
    await sleep(10);
    await assert.rejects(wait(), { message: "Too many tool calls at once for this user, wait for the running ones." });
    churned.leaveCall(other.identity);
    await queue[0];
    churned.shutdown();
  });

  it("reports a describe_entity cancelled while labels load as a failed call, not as a description with a warning", async () => {
    const session = await connect(sharedFor());
    try {
      await callTool(session.client, "describe_entity", { entity: "CustomersV3", fields: "x" }); // the entity is cached, its field labels are not
      cloud.faults.metadataDelayMs = 1500;
      const controller = new AbortController();
      const call = session.client.callTool({ name: "describe_entity", arguments: { entity: "CustomersV3" } }, undefined, { signal: controller.signal });
      await until(() => cloud.seen.foRequests.some((r) => r.path.startsWith("/Metadata/Labels(Id='@TST_CustomerAccount'")), "the field labels to be requested");
      controller.abort();
      await assert.rejects(call);
      await until(() => session.events.length === 2, "the audit event of the cancelled call");
      assert.deepEqual([session.events[1].tool, session.events[1].ok, session.events[1].error], ["describe_entity", false, "The tool call was cancelled."]);
    } finally {
      cloud.faults.metadataDelayMs = 0;
      await session.close();
    }
  });

  it("does not start a POST or PATCH with less than 5 seconds of the budget left, and says that nothing was sent", async () => {
    const fo = new FoClient(sharedFor({ FO_TIMEOUT_MS: "10000" }), serviceToken);
    const post = (waitMs) =>
      fo.withBudget(async () => {
        await sleep(waitMs); // stands for the reads a write tool makes first
        return fo.request("/data/CustomerGroups", { method: "POST", body: { CustomerGroupId: String(waitMs), dataAreaId: "USMF" } });
      });
    const [late, inTime] = await Promise.allSettled([post(5300), post(4300)]);
    assert.equal(late.status, "rejected");
    assert.match(
      late.reason.message,
      /^POST \/data\/CustomerGroups was not sent, so nothing changed in F&O: only 4\.\d s of the 10 s a tool call may take were left, too little for F&O to answer a write\. Try again in a moment\.$/
    );
    assert.equal(late.reason.outcomeUnknown, false);
    assert.equal(inTime.status, "fulfilled", inTime.reason?.message);
    assert.deepEqual(cloud.seen.foRequests.filter((r) => r.method === "POST").map((r) => JSON.parse(r.body).CustomerGroupId), ["4300"]);
  });

  /**
   * Read /data/BigRows in this many tool calls at once. Every call keeps what it read until all of them got their answer
   * or their error, as a tool call keeps its rows.
   */
  async function readTogether(fo, calls) {
    let arrived = 0;
    let allArrived;
    const barrier = new Promise((resolve) => (allArrived = resolve));
    return Promise.allSettled(
      Array.from({ length: calls }, () =>
        fo.withBudget(async () => {
          try {
            return (await fo.requestCollection("/data/BigRows")).value.length;
          } finally {
            if (++arrived === calls) allArrived();
            await barrier;
          }
        })
      )
    );
  }

  it("fails reads with server busy once the F&O answers held by all calls reach 96 MB, and lets go of them when the calls end", async () => {
    cloud.faults.bigRows = 38; // about 3.8 MB, under the 4 MB limit of one answer
    const fo = new FoClient(sharedFor(), serviceToken);
    const results = await readTogether(fo, 28); // about 106 MB together
    const read = results.filter((r) => r.status === "fulfilled");
    const busy = results.filter((r) => r.status === "rejected");
    assert.ok(busy.length >= 3, `about 10 MB over the limit must fail at least three calls, ${busy.length} failed`);
    assert.ok(read.length >= 1 && read.length <= 25, `${read.length} calls read their answer`);
    for (const r of busy) {
      assert.equal(r.reason.message, "The server is busy reading other large F&O answers. Try again in a moment, or pass select with the fields you need and a smaller top.");
    }
    // Answers over 4 MB fail after about 4 MB were read. What a failed read held is let go at once, not kept.
    cloud.faults.bigRows = 90;
    for (let i = 0; i < 10; i++) await assert.rejects(fo.withBudget(() => fo.requestCollection("/data/BigRows")), /\/data\/BigRows is over 4 MB/);
    // Once the calls ended, their bytes are free again: 25 calls of 3.8 MB at once, 95 MB, just fit under the 96 MB.
    // Under heavy load a connection can still break now and then, which says nothing about the bytes held.
    cloud.faults.bigRows = 38;
    const again = await readTogether(fo, 25);
    assert.deepEqual(again.filter((r) => r.reason?.message.startsWith("The server is busy")).map((r) => r.reason.message), [], "no call is refused as busy");
    assert.ok(again.filter((r) => r.value === 38).length >= 23, again.map((r) => r.reason?.message ?? r.value).join(", "));
  });

  it("reports a describe_entity cancelled while only enum values load as a failed call", async () => {
    const session = await connect(sharedFor());
    try {
      // The labels of the entity and of Blocked are cached now, its enum values are not.
      await callTool(session.client, "describe_entity", { entity: "CustomersV3", fields: "blocked", includeEnumValues: false });
      cloud.reset();
      cloud.faults.metadataDelayMs = 1500;
      const controller = new AbortController();
      const call = session.client.callTool({ name: "describe_entity", arguments: { entity: "CustomersV3", fields: "blocked" } }, undefined, { signal: controller.signal });
      await until(() => cloud.seen.foRequests.some((r) => r.path.startsWith("/Metadata/PublicEnumerations")), "the enum values to be requested");
      assert.deepEqual(cloud.seen.foRequests.map((r) => r.path), ["/Metadata/PublicEnumerations('CustVendorBlocked')"], "only the enum is loaded");
      controller.abort();
      await assert.rejects(call);
      await until(() => session.events.length === 2, "the audit event of the cancelled call");
      assert.deepEqual([session.events[1].ok, session.events[1].error], [false, "The tool call was cancelled."]);
    } finally {
      cloud.faults.metadataDelayMs = 0;
      await session.close();
    }
  });

  it("ends environment_info and the legal entity hint of query_entity as stopped on a shutdown or a cancel, not as a success", async () => {
    const shared = sharedFor();
    const session = await connect(shared);
    try {
      await callTool(session.client, "environment_info"); // the entity list and the legal entities are cached now
      cloud.reset();
      cloud.faults.dataDelayMs = 1500;
      const controller = new AbortController();
      const cancelled = session.client.callTool({ name: "environment_info", arguments: {} }, undefined, { signal: controller.signal });
      await until(() => cloud.seen.foRequests.filter((r) => r.method === "POST").length === 2, "the version actions to reach F&O");
      controller.abort();
      await assert.rejects(cancelled);
      await until(() => session.events.length === 2, "the audit event of the cancelled call");
      assert.deepEqual([session.events[1].ok, session.events[1].error], [false, "The tool call was cancelled. F&O may still have run the action."]);

      cloud.reset();
      cloud.faults.dataDelayMs = 1500;
      const stopped = callToolRaw(session.client, "environment_info");
      await until(() => cloud.seen.foRequests.filter((r) => r.method === "POST").length === 2, "the version actions to reach F&O");
      shared.shutdown();
      assert.deepEqual(await stopped, { isError: true, text: "The server is restarting, so the tool call was stopped. F&O may still have run the action." });
      assert.equal(session.events[2].ok, false);
    } finally {
      cloud.faults.dataDelayMs = 0;
      await session.close();
    }

    // query_entity finds no rows for a company and asks for the legal entities to say whether it exists.
    const other = sharedFor();
    const reader = await connect(other);
    try {
      await callTool(reader.client, "describe_entity", { entity: "CustomersV3", fields: "x" }); // the metadata is cached, the legal entities are not
      cloud.faults.dataDelayMs = 1000;
      const call = callToolRaw(reader.client, "query_entity", { entity: "CustomersV3", company: "XXXX", select: "CustomerAccount" });
      await until(() => cloud.seen.foRequests.some((r) => r.path.startsWith("/data/LegalEntities")), "the legal entities to be requested");
      other.shutdown();
      assert.deepEqual(await call, { isError: true, text: "The server is restarting, so the tool call was stopped. Call the tool again in a moment." });
      assert.equal(reader.events.at(-1).ok, false);
    } finally {
      cloud.faults.dataDelayMs = 0;
      await reader.close();
    }
  });

  it("lets a create or update already sent finish within the grace of a shutdown and stops it once the grace is over", async () => {
    const shared = sharedFor({ FO_ALLOW_WRITES: "1" });
    const session = await connect(shared);
    try {
      await callTool(session.client, "describe_entity", { entity: "CustomerGroups", fields: "x" }); // the metadata is cached now
      cloud.reset();
      cloud.faults.dataDelayMs = 1000;
      const create = callToolRaw(session.client, "create_record", { entity: "CustomerGroups", data: { CustomerGroupId: "88" } });
      const update = callToolRaw(session.client, "update_record", { entity: "CustomerGroups", key: { CustomerGroupId: "20" }, data: { Description: "Retail and web" } });
      await until(() => ["POST", "PATCH"].every((method) => cloud.seen.foRequests.some((r) => r.method === method)), "the POST and the PATCH to reach F&O");
      const read = callToolRaw(session.client, "query_entity", { entity: "CustomerGroups", select: "CustomerGroupId" });
      await until(() => cloud.seen.foRequests.some((r) => r.method === "GET" && r.path.startsWith("/data/CustomerGroups?")), "the read to reach F&O");
      const started = Date.now();
      shared.shutdown(5000);
      assert.deepEqual(await read, { isError: true, text: "The server is restarting, so the tool call was stopped. Call the tool again in a moment." });
      assert.ok(Date.now() - started < 500, "a read stops at once");
      const created = await create;
      assert.equal(created.isError, false, created.text);
      assert.equal(JSON.parse(created.text).key.CustomerGroupId, "88");
      const updated = await update;
      assert.equal(updated.isError, false, updated.text);
      const answer = JSON.parse(updated.text);
      assert.deepEqual(answer.before, { Description: "Retail" });
      assert.equal(answer.note, "The update went through, but the tool call was stopped before the record could be read again.");
      assert.equal(cloud.tables.CustomerGroups.find((g) => g.CustomerGroupId === "20").Description, "Retail and web");
      const audited = (tool) => session.events.find((e) => e.tool === tool);
      for (const tool of ["create_record", "update_record"]) assert.deepEqual([audited(tool).ok, audited(tool).sent, audited(tool).outcome], [true, true, undefined], tool);
    } finally {
      cloud.faults.dataDelayMs = 0;
      await session.close();
    }

    // A write whose answer takes longer than the grace is stopped once the grace is over, with its outcome open.
    const late = sharedFor({ FO_ALLOW_WRITES: "1" });
    const writer = await connect(late);
    try {
      await callTool(writer.client, "describe_entity", { entity: "CustomerGroups", fields: "x" });
      cloud.reset();
      cloud.faults.dataDelayMs = 5000;
      const create = callToolRaw(writer.client, "create_record", { entity: "CustomerGroups", data: { CustomerGroupId: "89" } });
      await until(() => cloud.seen.foRequests.some((r) => r.method === "POST"), "the POST to reach F&O");
      const started = Date.now();
      late.shutdown(300);
      assert.deepEqual(await create, {
        isError: true,
        text: "The server is restarting, so the tool call was stopped. F&O may still have processed the request, so check with query_entity before repeating a create.",
      });
      assert.ok(Date.now() - started >= 250 && Date.now() - started < 2000, `stopped after the grace, ${Date.now() - started} ms`);
      const event = writer.events.find((e) => e.tool === "create_record");
      assert.deepEqual([event.ok, event.outcome, event.sent], [false, "unknown", true]);
    } finally {
      cloud.faults.dataDelayMs = 0;
      await writer.close();
    }
  });

  it("still asks F&O for the versions when a slow first metadata load leaves less than the minimum of a write", async () => {
    const session = await connect(sharedFor({ FO_TIMEOUT_MS: "3000" }));
    try {
      cloud.faults.metadataDelayMs = 1700; // 1.3 s of the 3 s are left, under the 1.5 s a write needs with this budget
      const info = await callTool(session.client, "environment_info");
      assert.deepEqual([info.applicationVersion, info.platformVersion], ["10.0.48", "7.0.7521.0"]);
      assert.equal("problems" in info, false, JSON.stringify(info.problems));
    } finally {
      cloud.faults.metadataDelayMs = 0;
      await session.close();
    }
  });

  it("does not mark a write as sent in the audit when the connection to F&O could not be made", async () => {
    const closed = await freePort(); // nothing listens there
    const shared = new FoShared(
      loadConfig({ FO_URL: `https://127.0.0.1:${closed}`, FO_TENANT_ID: tenantId, FO_CLIENT_ID: clientId, FO_CLIENT_SECRET: clientSecret, FO_COMPANY: "USMF", FO_ALLOW_WRITES: "1" })
    );
    // The metadata the write tools need, as if F&O had answered it before it went down.
    const caches = shared.cachesFor("service");
    caches.entityCache = { value: DATA_ENTITIES, fetchedAt: Date.now() };
    caches.publicEntityCache.set("CustomerGroups", { value: PUBLIC_ENTITIES.CustomerGroups, fetchedAt: Date.now() });
    const session = await connect(shared);
    try {
      const { text, isError } = await callToolRaw(session.client, "create_record", { entity: "CustomerGroups", data: { CustomerGroupId: "77" } });
      assert.equal(isError, true);
      assert.match(text, /^Request to https:\/\/127\.0\.0\.1:\d+\/data\/CustomerGroups failed: fetch failed \(ECONNREFUSED/);
      assert.doesNotMatch(text, /may still have/);
      const [event] = session.events;
      assert.deepEqual([event.tool, event.ok, event.sent, event.outcome], ["create_record", false, undefined, undefined]);
    } finally {
      await session.close();
    }
  });

  it("takes a dataAreaId of null or empty text in a write as no legal entity, so the default company applies", async () => {
    const session = await connect(sharedFor({ FO_ALLOW_WRITES: "1" }));
    try {
      const updated = await callTool(session.client, "update_record", { entity: "CustomerGroups", key: { CustomerGroupId: "10" }, data: { dataAreaId: null, Description: "Wholesale and web" } });
      assert.deepEqual(updated.key, { dataAreaId: "USMF", CustomerGroupId: "10" });
      const blank = await callTool(session.client, "update_record", { entity: "CustomerGroups", key: { dataAreaId: "", CustomerGroupId: "20" }, data: { Description: "Retail and web" } });
      assert.deepEqual(blank.key, { dataAreaId: "USMF", CustomerGroupId: "20" });
      const created = await callTool(session.client, "create_record", { entity: "CustomerGroups", data: { dataAreaId: null, CustomerGroupId: "77" } });
      assert.equal(created.key.dataAreaId, "usmf");
      const writes = cloud.seen.foRequests.filter((r) => r.method !== "GET").map((r) => `${r.method} ${r.path} ${r.body}`);
      assert.deepEqual(writes, [
        `PATCH /data/CustomerGroups(dataAreaId='USMF',CustomerGroupId='10')?cross-company=true {"Description":"Wholesale and web"}`,
        `PATCH /data/CustomerGroups(dataAreaId='USMF',CustomerGroupId='20')?cross-company=true {"Description":"Retail and web"}`,
        `POST /data/CustomerGroups {"dataAreaId":"USMF","CustomerGroupId":"77"}`,
      ]);
    } finally {
      await session.close();
    }
  });

  it("keeps at most 200 entities per identity in its metadata cache and drops the least recently used first", async () => {
    const fo = new FoClient(sharedFor(), serviceToken);
    const names = Array.from({ length: 201 }, (_, i) => `Synthetic${i}`);
    for (const name of names) PUBLIC_ENTITIES[name] = { ...PUBLIC_ENTITIES.Currencies, Name: name, EntitySetName: name };
    try {
      for (const name of names.slice(0, 200)) await fo.getPublicEntity(name);
      await fo.getPublicEntity("Synthetic0"); // used again, so Synthetic1 is now the least recently used
      await fo.getPublicEntity("Synthetic200"); // the 201st pushes Synthetic1 out
      cloud.reset();
      for (const name of ["Synthetic0", "Synthetic2", "Synthetic200"]) assert.equal((await fo.getPublicEntity(name)).EntitySetName, name);
      assert.deepEqual(cloud.seen.foRequests, [], "these come from the cache");
      await fo.getPublicEntity("Synthetic1");
      assert.deepEqual(cloud.seen.foRequests.map((r) => r.path), ["/Metadata/PublicEntities?$filter=EntitySetName eq 'Synthetic1'"]);
    } finally {
      for (const name of names) delete PUBLIC_ENTITIES[name];
    }
  });

  it("lets identities that get the same entity list from F&O share one parsed copy, and keeps a different list apart", async () => {
    const shared = sharedFor();
    const [alice, bob, carol] = ["alice", "bob", "carol"].map((user) => new FoClient(shared, serviceToken, user, `oid-${user}`));
    const forAlice = await alice.listEntities();
    const forBob = await bob.listEntities();
    assert.equal(forBob, forAlice, "one array for both, not a copy each");
    assert.equal(cloud.seen.foRequests.filter((r) => r.path === "/Metadata/DataEntities").length, 2, "each identity still asks F&O itself");
    cloud.faults.dataEntitiesPadBytes = 10;
    const forCarol = await carol.listEntities();
    assert.notEqual(forCarol, forAlice);
    assert.equal(forCarol.length, forAlice.length + 1);
  });

  it("fails a refresh of the entity list with the 401 or 403 F&O answers instead of serving the old list, and logs a refresh that F&O was down for", async () => {
    const shared = sharedFor();
    const fo = new FoClient(shared, serviceToken);
    const entities = await fo.listEntities();
    const caches = shared.cachesFor("service");
    const loads = () => cloud.seen.foRequests.filter((r) => r.path === "/Metadata/DataEntities").length;
    // The identity lost its F&O user. The old list once hid that from search_entities for as long as the identity kept calling.
    caches.entityCache.fetchedAt = Date.now() - 11 * 60_000;
    cloud.faults.foStatus = 403;
    cloud.faults.foBody = { Message: "Please verify that the user is valid and set up correctly." };
    await assert.rejects(fo.listEntities(), { message: "GET /Metadata/DataEntities failed with 403: Please verify that the user is valid and set up correctly.", status: 403 });
    await assert.rejects(fo.listEntities(), { status: 403 }); // a refusal is not backed off like an outage, F&O is asked again
    assert.equal(loads(), 3);
    cloud.faults.foStatus = 401;
    cloud.faults.foBody = undefined;
    await assert.rejects(fo.listEntities(), { message: /^GET \/Metadata\/DataEntities failed with 401: F&O rejected the token of the signed in user\./, status: 401 });
    // F&O is down: the old list stays in use for 30 seconds, and the operator gets one line about it.
    cloud.faults.foStatus = 503;
    const lines = [];
    const original = console.error;
    console.error = (line) => lines.push(String(line));
    try {
      assert.equal(await fo.listEntities(), entities, "the old list");
    } finally {
      console.error = original;
    }
    assert.equal(lines.length, 1, lines.join("\n"));
    assert.match(
      lines[0],
      /^fo-mcp: the entity list of service could not be refreshed, the list read at \d{4}-\d{2}-\d{2}T[\d:.]+Z stays in use: GET \/Metadata\/DataEntities failed with 503: An error has occurred\.$/
    );
    cloud.faults.foStatus = undefined;
    const before = loads();
    assert.equal(await fo.listEntities(), entities, "still the old list while the refresh backs off");
    assert.equal(loads(), before, "no request within the 30 seconds");
  });

  it("answers an entity name that is not on the list from the cached list at once, and refreshes the list behind the answer at most every three minutes", async () => {
    const shared = sharedFor();
    const fo = new FoClient(shared, serviceToken);
    await fo.listEntities();
    const caches = shared.cachesFor("service");
    const loads = () => cloud.seen.foRequests.filter((r) => r.path === "/Metadata/DataEntities").length;
    const notFound = { message: "Entity 'CustTable' not found. Did you mean CustomersV3, CustomerGroups? Use search_entities to look further." };
    cloud.reset();
    // Older than the 30 seconds after which a miss once downloaded the whole list again, every time.
    caches.entityCache.fetchedAt = Date.now() - 2 * 60_000;
    await assert.rejects(fo.resolveEntitySet("CustTable"), notFound);
    assert.deepEqual(cloud.seen.foRequests, [], "a miss on a list under three minutes old asks F&O nothing");
    // Past three minutes the miss is answered as fast, while the list is refreshed behind it: an entity deployed meanwhile.
    caches.entityCache.fetchedAt = Date.now() - 4 * 60_000;
    cloud.faults.metadataDelayMs = 1000;
    cloud.faults.dataEntitiesPadBytes = 10;
    const started = Date.now();
    await assert.rejects(fo.resolveEntitySet("CustTable"), notFound);
    assert.ok(Date.now() - started < 500, `the miss does not wait for the download, ${Date.now() - started} ms`);
    await until(() => loads() === 1, "the download behind the answer");
    await assert.rejects(fo.resolveEntitySet("Paddings"), { message: "Entity 'Paddings' not found. Use search_entities to look further." }); // a miss while the load runs joins it
    assert.equal(loads(), 1, "no second download");
    await until(() => caches.entityFetch === undefined, "the refresh to finish");
    assert.ok((await fo.listEntities()).some((e) => e.PublicCollectionName === "Paddings"), "the next call sees the new entity");
    assert.equal(loads(), 1, "from the refreshed list, without another download");
    // The list was just refreshed, so the next miss starts nothing. Nor does one while a failed refresh backs off.
    await assert.rejects(fo.resolveEntitySet("CustTable"), notFound);
    caches.entityCache.fetchedAt = Date.now() - 4 * 60_000;
    caches.entityRefreshFailedAt = Date.now();
    await assert.rejects(fo.resolveEntitySet("CustTable"), notFound);
    assert.equal(loads(), 1);
    // A refresh F&O refuses leaves the list as old as it was. The time of the attempt spaces the next one, or every
    // guess of an identity that lost its access would ask F&O again, and the operator gets the reason nobody waited for.
    caches.entityRefreshFailedAt = 0;
    caches.entityMissRefreshAt = 0;
    cloud.faults.metadataDelayMs = 0;
    cloud.faults.foStatus = 403;
    cloud.faults.foBody = { Message: "Please verify that the user is valid and set up correctly." };
    const lines = [];
    const original = console.error;
    console.error = (line) => lines.push(String(line));
    try {
      await assert.rejects(fo.resolveEntitySet("CustTable"), notFound);
      await until(() => lines.length === 1, "the line about the refused refresh");
      for (let i = 0; i < 3; i++) await assert.rejects(fo.resolveEntitySet(`Guess${i}`), { message: /not found/ });
      await sleep(100);
    } finally {
      console.error = original;
      cloud.faults.foStatus = undefined;
      cloud.faults.foBody = undefined;
    }
    assert.equal(loads(), 2, "one refused refresh, not one per guess");
    assert.deepEqual(lines, ["fo-mcp: the entity list of service was not refreshed after a name it does not have: GET /Metadata/DataEntities failed with 403: Please verify that the user is valid and set up correctly."]);
    // A list answer that arrived and is no list is an answer too, not an outage the old list may cover.
    caches.entityCache.fetchedAt = Date.now() - 11 * 60_000;
    cloud.faults.foStatus = 200;
    cloud.faults.foBody = { notValue: true };
    try {
      const before = loads();
      await assert.rejects(fo.listEntities(), { message: /returned no value array/, status: 200 });
      assert.equal(loads(), before + 1);
      // Asked again at once it fails the same way without another download, which for an answer over 20 MB would be one each.
      await assert.rejects(fo.listEntities(), { message: /returned no value array/, status: 200 });
      await assert.rejects(fo.resolveEntitySet("CustomersV3"), { message: /returned no value array/ });
      assert.equal(loads(), before + 1, "no second download within the 30 seconds");
    } finally {
      cloud.faults.foStatus = undefined;
      cloud.faults.foBody = undefined;
    }
  });

  it("keeps at most 5000 labels and 5000 enum definitions for every identity together and drops the least recently used first", async () => {
    const shared = sharedFor();
    const fo = new FoClient(shared, serviceToken);
    await fo.getLabel("@TST_First"); // the oldest entry until it is used again
    const ids = Array.from({ length: 4999 }, (_, i) => `@TST_Label${i}`);
    assert.equal((await fo.getLabels(ids)).labels.size, 4999);
    assert.equal(shared.labelCache.size, 5000);
    await fo.getLabel("@TST_First"); // used again, so one of the others is now the least recently used
    await fo.getLabel("@TST_Last"); // the 5001st pushes it out
    assert.equal(shared.labelCache.size, 5000);
    cloud.reset();
    assert.deepEqual([await fo.getLabel("@TST_First"), await fo.getLabel("@TST_Last")], ["First (en-US)", "Last (en-US)"]);
    assert.deepEqual(cloud.seen.foRequests, [], "these come from the cache");
    await fo.getLabels(ids);
    assert.equal(cloud.seen.foRequests.length, 1, "exactly one of the others was dropped");
    assert.match(cloud.seen.foRequests[0].path, /^\/Metadata\/Labels\(Id='@TST_Label\d+',Language='en-US'\)$/);

    // The same for the enums, which are bounded by the number of enums in F&O, but by this cap too.
    const names = Array.from({ length: 5001 }, (_, i) => `Synthetic${i}`);
    for (const name of names) cloud.enums[name] = ["No", "Yes"];
    await fo.getEnumeration("Synthetic0");
    assert.equal((await fo.getEnumerations(names.slice(1, 5000), 12)).enums.size, 4999);
    await fo.getEnumeration("Synthetic0");
    await fo.getEnumeration("Synthetic5000");
    assert.equal(shared.enumCache.size, 5000);
    cloud.reset();
    for (const name of names) cloud.enums[name] = ["No", "Yes"];
    assert.equal((await fo.getEnumeration("Synthetic0")).Name, "Synthetic0");
    assert.equal((await fo.getEnumeration("Synthetic5000")).Name, "Synthetic5000");
    assert.deepEqual(cloud.seen.foRequests, [], "these come from the cache");
    await fo.getEnumerations(names.slice(1, 5000), 12);
    assert.equal(cloud.seen.foRequests.length, 1, "exactly one of the others was dropped");
  });
});
