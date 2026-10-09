// Limits and failure handling of the F&O client: the size cap on one answer (4 MB from /data, 20 MB from /Metadata),
// the time budget of a tool call, a 401 from F&O with its single retry and the hint for each mode, throttling, redirects,
// broken connections, the number of calls at once and the queue past it, a failing Entra token endpoint, error pages from
// a proxy, certificate validation towards F&O, the F&O host name behind FO_HOST_IP and HTTPS_PROXY and configuration
// values that must stop the server at start. Mostly through the local stdio server (dist/index.js) against the fake
// cloud in test/support.mjs.
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { readFileSync } from "node:fs";
import { createServer as createHttpServer } from "node:http";
import { createServer as createHttpsServer } from "node:https";
import { connect } from "node:net";
import { join } from "node:path";
import { performance } from "node:perf_hooks";
import { after, before, beforeEach, describe, it } from "node:test";
import { FoShared, loadConfig } from "../dist/fo.js";
import {
  callTool, callToolRaw, clientId, clientSecret, connectWithSignIn, freePort, listenOn, makeCert, makeProvider, NO_OPENSSL, projectDir, serverEnv, sleep, startFakeCloud,
  startServer, startStdio, SUITE_TIMEOUT, tenantId,
} from "./support.mjs";

const OBO_GRANT = "urn:ietf:params:oauth:grant-type:jwt-bearer";
const escapeRegExp = (text) => text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
const UPDATE_NOTE = "F&O may still have applied the update, read the record before trying again.";

/**
 * Run a server script directly and collect its output. Resolves when the process has exited, or, when `readyLine`
 * is given, as soon as stderr contains it (the process is then killed). Fails after `limitMs`.
 */
function runScript(script, env, { readyLine, limitMs = 10_000 } = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [join(projectDir, script)], { cwd: projectDir, env, stdio: ["pipe", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    let ready = false;
    const timer = setTimeout(() => {
      child.kill();
      reject(new Error(`${script} neither exited nor got ready within ${limitMs} ms. stderr:\n${stderr}`));
    }, limitMs);
    child.stdout.on("data", (d) => (stdout += d));
    child.stderr.on("data", (d) => {
      stderr += d;
      if (readyLine && !ready && stderr.includes(readyLine)) {
        ready = true;
        child.kill();
      }
    });
    child.on("close", (code, signal) => {
      clearTimeout(timer);
      resolve({ code, signal, stdout, stderr, ready });
    });
  });
}

describe("limits and failure handling of the F&O client", { timeout: SUITE_TIMEOUT, skip: NO_OPENSSL }, () => {
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

  /** Start a fresh stdio server for one test, so its token and metadata caches start empty, and always close it. */
  async function withStdio(env, run) {
    const stdio = await startStdio({ cloud, certFile: cert.certFile, env });
    try {
      return await run(stdio);
    } finally {
      await stdio.close();
    }
  }

  /**
   * A stand-in Entra token endpoint for FO_AUTHORITY that issues the same client credentials token as the fake cloud,
   * but answers the nth token request only after delayFor(n) ms. The fake cloud has no fault for a slow token endpoint.
   */
  async function startSlowEntra(delayFor) {
    const grants = [];
    const timers = new Set();
    const server = createHttpsServer({ key: readFileSync(join(cert.dir, "key.pem")), cert: readFileSync(cert.certFile) }, (req, res) => {
      let body = "";
      req.on("data", (c) => (body += c));
      req.on("end", () => {
        grants.push(new URLSearchParams(body).get("grant_type"));
        const timer = setTimeout(() => {
          timers.delete(timer);
          if (res.destroyed) return;
          res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify({ token_type: "Bearer", access_token: "fo-token-for-service", expires_in: 3600 }));
        }, delayFor(grants.length));
        timers.add(timer);
      });
    });
    const port = await listenOn(server);
    return {
      authority: `https://localhost:${port}`,
      grants,
      close: () => new Promise((resolve) => {
        for (const timer of timers) clearTimeout(timer);
        server.closeAllConnections();
        server.close(resolve);
      }),
    };
  }

  it("refuses an F&O answer over 4 MB with a hint to pass select, and the server keeps serving the next call", async () => {
    await withStdio({}, async ({ client }) => {
      cloud.faults.bigRows = 50; // about 5 MB, which was read in full while the limit was 8 MB
      const { text, isError } = await callToolRaw(client, "query_entity", { entity: "BigRows" });
      assert.equal(isError, true, text);
      assert.equal(
        text,
        `The answer from ${cloud.foUrl}/data/BigRows?$top=20 is over 4 MB. Pass select with the fields you need, a smaller top, ` +
          "or select inside expand, for example expand=SalesOrderLines($select=ItemNumber,OrderedSalesQuantity)."
      );
      const bigRequests = cloud.seen.foRequests.filter((r) => r.path.startsWith("/data/BigRows"));
      assert.deepEqual(bigRequests.map((r) => `${r.method} ${r.path}`), ["GET /data/BigRows?$top=20"], "one request, not repeated");

      // The process survived reading 4 MB and stopping: the same client gets an answer for the next call.
      const currencies = await callTool(client, "query_entity", { entity: "Currencies" });
      assert.deepEqual(currencies.rows, [{ CurrencyCode: "EUR", Name: "Euro" }, { CurrencyCode: "USD", Name: "US Dollar" }]);
    });
  });

  it("stops waiting for F&O after FO_TIMEOUT_MS with a clear message, and the next call works once F&O is fast again", async () => {
    await withStdio({ FO_TIMEOUT_MS: "1500" }, async ({ client }) => {
      cloud.faults.dataDelayMs = 3000;
      const args = { entity: "CustomersV3", select: "CustomerAccount" };
      const started = performance.now();
      const { text, isError } = await callToolRaw(client, "query_entity", args);
      const elapsed = performance.now() - started;
      assert.equal(isError, true, text);
      assert.equal(
        text,
        `No answer from ${cloud.foUrl}/data/CustomersV3?$filter=dataAreaId eq 'USMF'&$select=CustomerAccount&$top=20&cross-company=true ` +
          "within the 1.5 s a tool call may take. The first call after a restart can be slow, try again."
      );
      assert.ok(elapsed >= 1400, `the call must wait for the budget, it gave up after ${Math.round(elapsed)} ms`);
      assert.ok(elapsed < 2500, `the call must give up at the 1.5 s budget, not wait for the 3 s answer, it took ${Math.round(elapsed)} ms`);

      cloud.faults.dataDelayMs = 0;
      const result = await callTool(client, "query_entity", args);
      assert.deepEqual(result.rows.map((r) => r.CustomerAccount), ["US-001", "US-002", "US-003"]);
      const dataRequests = cloud.seen.foRequests.filter((r) => r.path.startsWith("/data/CustomersV3"));
      assert.equal(dataRequests.length, 2, "the timed out request was not repeated within the call");
    });
  });

  it("shares one time budget between the sequential requests of a tool call and gives every call a new one", async () => {
    await withStdio({ FO_TIMEOUT_MS: "1500" }, async ({ client }) => {
      // Each Metadata request alone fits in 1.5 s, the entity list followed by the entity details does not.
      cloud.faults.metadataDelayMs = 1000;
      const started = performance.now();
      const { text, isError } = await callToolRaw(client, "describe_entity", { entity: "CustomersV3" });
      const elapsed = performance.now() - started;
      assert.equal(isError, true, text);
      assert.equal(
        text,
        `No answer from ${cloud.foUrl}/Metadata/PublicEntities?$filter=EntitySetName eq 'CustomersV3' within the 1.5 s a tool call may take. ` +
          "The first call after a restart can be slow, try again."
      );
      assert.ok(elapsed < 1950, `the second request must only get what is left of the budget, the call took ${Math.round(elapsed)} ms`);
      assert.deepEqual(
        cloud.seen.foRequests.map((r) => r.path),
        ["/Metadata/DataEntities", "/Metadata/PublicEntities?$filter=EntitySetName eq 'CustomersV3'"],
        "the entity list arrived within the budget, the details request was cut off and no label request started"
      );

      // The next call starts with a full budget. The entity list is cached now, details and labels fit in 1.5 s.
      cloud.faults.metadataDelayMs = 500;
      const described = await callTool(client, "describe_entity", { entity: "CustomersV3" });
      assert.equal(described.label, "CustomerV3 (en-US)");
      assert.equal(described.warning, undefined, "every label arrived within the new budget");
      assert.equal(cloud.seen.foRequests.filter((r) => r.path === "/Metadata/DataEntities").length, 1, "the entity list came from the cache");
    });
  });

  it("warns that a create which timed out may still have gone through, and sends it only once", async () => {
    await withStdio({ FO_ALLOW_WRITES: "1", FO_TIMEOUT_MS: "1500" }, async ({ client }) => {
      cloud.faults.dataDelayMs = 3000;
      const { text, isError } = await callToolRaw(client, "create_record", { entity: "CustomerGroups", data: { CustomerGroupId: "40", Description: "Slow" } });
      assert.equal(isError, true, text);
      assert.equal(
        text,
        `No answer from ${cloud.foUrl}/data/CustomerGroups within the 1.5 s a tool call may take. ` +
          "F&O may still have processed the request, so check with query_entity before repeating a create."
      );
      assert.doesNotMatch(text, /try again/, "a create must not be presented as safe to repeat");
      const posts = cloud.seen.foRequests.filter((r) => r.method === "POST");
      assert.equal(posts.length, 1);
      assert.deepEqual(JSON.parse(posts[0].body), { CustomerGroupId: "40", Description: "Slow", dataAreaId: "USMF" });
    });
  });

  it("warns that an update which timed out may have been applied instead of saying try again, and sends it only once", async () => {
    await withStdio({ FO_ALLOW_WRITES: "1", FO_TIMEOUT_MS: "3000" }, async ({ client }) => {
      cloud.faults.afterPatch = () => sleep(4000); // F&O applies the change and answers after the budget
      const { text, isError } = await callToolRaw(client, "update_record", { entity: "CustomerGroups", key: { CustomerGroupId: "10" }, data: { Description: "Late" } });
      assert.equal(isError, true, text);
      assert.equal(
        text,
        `No answer from ${cloud.foUrl}/data/CustomerGroups(dataAreaId='USMF',CustomerGroupId='10')?cross-company=true within the 3 s a tool call may take. ${UPDATE_NOTE}`
      );
      assert.doesNotMatch(text, /restart can be slow|try again\./, "an update must not be presented as not done");
      assert.equal(cloud.seen.foRequests.filter((r) => r.method === "PATCH").length, 1);
      assert.equal(cloud.tables.CustomerGroups[0].Description, "Late", "F&O did apply it");
    });
  });

  it("does not start a write when too little of the budget is left, and says that nothing was sent", async () => {
    await withStdio({ FO_ALLOW_WRITES: "1", FO_TIMEOUT_MS: "3000" }, async ({ client }) => {
      await callTool(client, "describe_entity", { entity: "CustomerGroups", fields: "x" }); // the metadata is cached now
      cloud.reset();
      cloud.faults.dataDelayMs = 1600; // the read before the write leaves 1.4 s, under the 1.5 s a write needs with a 3 s budget
      const { text, isError } = await callToolRaw(client, "update_record", { entity: "CustomerGroups", key: { CustomerGroupId: "10" }, data: { Description: "Never" } });
      assert.equal(isError, true, text);
      assert.match(
        text,
        /^PATCH \/data\/CustomerGroups\(dataAreaId='USMF',CustomerGroupId='10'\)\?cross-company=true was not sent, so nothing changed in F&O: only 1\.\d s of the 3 s a tool call may take were left, too little for F&O to answer a write\. Try again in a moment\.$/
      );
      assert.deepEqual(cloud.seen.foRequests.map((r) => r.method), ["GET"], "the record was read, the PATCH never went out");
      await sleep(200);
      assert.equal(cloud.tables.CustomerGroups[0].Description, "Wholesale");
    });
  });

  it("warns that an update may have been applied when the connection breaks after sending or a gateway fails", async () => {
    await withStdio({ FO_ALLOW_WRITES: "1" }, async ({ client }) => {
      cloud.faults.dropPatches = 1;
      const args = { entity: "CustomerGroups", key: { CustomerGroupId: "10" }, data: { Description: "Dropped" } };
      const dropped = await callToolRaw(client, "update_record", args);
      assert.equal(dropped.isError, true);
      assert.match(dropped.text, new RegExp(`^Request to ${escapeRegExp(cloud.foUrl)}/data/CustomerGroups\\(.*\\)\\?cross-company=true failed: `));
      assert.ok(dropped.text.endsWith(` ${UPDATE_NOTE}`), dropped.text);
      assert.equal(cloud.tables.CustomerGroups[0].Description, "Dropped", "F&O applied it before the connection broke");

      for (const status of [502, 503, 504]) {
        cloud.faults.throttle = { count: 1, status, method: "PATCH" };
        const gateway = await callToolRaw(client, "update_record", { ...args, data: { Description: `Gateway ${status}` } });
        assert.equal(
          gateway.text,
          `PATCH /data/CustomerGroups(dataAreaId='USMF',CustomerGroupId='10')?cross-company=true failed with ${status}: Too many requests, try again later. ${UPDATE_NOTE}`
        );
      }
      cloud.faults.throttle = { count: 1, status: 500, method: "PATCH" };
      const failed = await callToolRaw(client, "update_record", { ...args, data: { Description: "Refused" } });
      assert.doesNotMatch(failed.text, /may still have/, "a 500 is an answer of F&O itself");
    });
  });

  it("retries a 401 from F&O once with a fresh client credentials token, then points at the Microsoft Entra ID applications setup", async () => {
    await withStdio({}, async ({ client }) => {
      cloud.faults.foStatus = 401;
      const { text, isError } = await callToolRaw(client, "query_entity", { entity: "CustomersV3" });
      assert.equal(isError, true, text);
      assert.equal(
        text,
        `GET /Metadata/DataEntities failed with 401: F&O rejected the access token. Check that client ID ${clientId} is listed under ` +
          "System administration > Setup > Microsoft Entra ID applications and mapped to an enabled user."
      );
      assert.deepEqual(cloud.seen.tokenGrants, ["client_credentials", "client_credentials"], "one token for the first attempt and a fresh one for the retry");
      assert.deepEqual(
        cloud.seen.foRequests.map((r) => `${r.method} ${r.path}`),
        ["GET /Metadata/DataEntities", "GET /Metadata/DataEntities"],
        "exactly one retry"
      );
    });
  });

  it("repeats a write once after a 401 with a fresh token in place of the cached one", async () => {
    await withStdio({ FO_ALLOW_WRITES: "1" }, async ({ client }) => {
      await callTool(client, "describe_entity", { entity: "CustomerGroups" }); // caches the token and the metadata
      cloud.reset();
      cloud.faults.foStatus = 401;
      const data = { CustomerGroupId: "30", Description: "Refused" };
      const { text, isError } = await callToolRaw(client, "create_record", { entity: "CustomerGroups", data });
      assert.equal(isError, true, text);
      assert.match(text, /^POST \/data\/CustomerGroups failed with 401: F&O rejected the access token\. .*Microsoft Entra ID applications/);
      assert.deepEqual(cloud.seen.tokenGrants, ["client_credentials"], "the cached token is dropped and one fresh token is requested");
      assert.deepEqual(
        cloud.seen.foRequests.map((r) => [r.method, r.path, JSON.parse(r.body)]),
        [["POST", "/data/CustomerGroups", { ...data, dataAreaId: "USMF" }], ["POST", "/data/CustomerGroups", { ...data, dataAreaId: "USMF" }]],
        "the metadata came from the cache and the POST went out twice, the second time with the new token"
      );
    });
  });

  it("gives a signed in user of the remote server the delegated permissions hint on a 401, not the client credentials one", async () => {
    const server = await startServer({ cloud, certFile: cert.certFile });
    try {
      const client = await connectWithSignIn(server.url, makeProvider(cloud, "alice"));
      try {
        cloud.reset();
        cloud.faults.foStatus = 401;
        const { text, isError } = await callToolRaw(client, "query_entity", { entity: "CustomersV3" });
        assert.equal(isError, true, text);
        assert.equal(
          text,
          "GET /Metadata/DataEntities failed with 401: F&O rejected the token of alice@example.com. Check that FO_URL is the environment URL, " +
            "that the environment signs users in with the same Entra tenant and that the app registration has the Dynamics ERP delegated permissions with admin consent."
        );
        assert.doesNotMatch(text, /Microsoft Entra ID applications/);
        assert.doesNotMatch(text, new RegExp(clientId), "the client ID mapping is the client credentials setup, not the delegated one");
        assert.deepEqual(cloud.seen.tokenGrants, [OBO_GRANT, OBO_GRANT], "one on-behalf-of exchange for the first attempt and a fresh one for the retry");
        assert.deepEqual(
          cloud.seen.foRequests.map((r) => `${r.user} ${r.method} ${r.path}`),
          ["alice@example.com GET /Metadata/DataEntities", "alice@example.com GET /Metadata/DataEntities"]
        );
      } finally {
        await client.close();
      }
    } finally {
      await server.stop();
    }
  });

  it("names the Entra token request when client credentials are refused, without showing the secret", async () => {
    await withStdio({ FO_CLIENT_SECRET: "wrong-secret" }, async ({ client }) => {
      const { text, isError } = await callToolRaw(client, "query_entity", { entity: "CustomersV3" });
      assert.equal(isError, true, text);
      assert.equal(text, `Token request to ${cloud.origin}/${tenantId}/oauth2/v2.0/token failed with 401: invalid_client wrong client id or secret`);
      assert.doesNotMatch(text, /wrong-secret/);
      assert.deepEqual(cloud.seen.foRequests, [], "nothing goes to F&O without a token");
    });
  });

  it("names the Entra token request and the network error when Entra cannot be reached", async () => {
    const closedPort = await freePort(); // nothing listens there
    await withStdio({ FO_AUTHORITY: `https://127.0.0.1:${closedPort}` }, async ({ client }) => {
      const { text, isError } = await callToolRaw(client, "query_entity", { entity: "CustomersV3" });
      assert.equal(isError, true, text);
      assert.match(text, new RegExp(`^Token request to ${escapeRegExp(`https://127.0.0.1:${closedPort}/${tenantId}/oauth2/v2.0/token`)} failed: .*ECONNREFUSED`));
      assert.deepEqual(cloud.seen.foRequests, []);
    });
  });

  it("gives up on an Entra token endpoint that does not answer within the budget and names the token request", async () => {
    const entra = await startSlowEntra(() => 5000);
    try {
      await withStdio({ FO_TIMEOUT_MS: "1500", FO_AUTHORITY: entra.authority }, async ({ client }) => {
        const started = performance.now();
        const { text, isError } = await callToolRaw(client, "query_entity", { entity: "CustomersV3" });
        const elapsed = performance.now() - started;
        assert.equal(isError, true, text);
        // Either the token request's own timeout or the call's budget fires first, both name the token request.
        assert.match(text, new RegExp(`^Token request to ${escapeRegExp(`${entra.authority}/${tenantId}/oauth2/v2.0/token`)} failed: .*timeout|^No answer from the Entra token endpoint within the 1.5 s`, "i"));
        assert.ok(elapsed < 2500, `the call must give up at the 1.5 s budget, it took ${Math.round(elapsed)} ms`);
        assert.deepEqual(entra.grants, ["client_credentials"]);
        assert.deepEqual(cloud.seen.foRequests, [], "nothing goes to F&O without a token");
      });
    } finally {
      await entra.close();
    }
  });

  it("keeps a token request that starts late in a call, for the retry after a 401, within what is left of the budget", async () => {
    // The first token comes at once, the fresh one for the retry takes longer than the whole budget.
    const entra = await startSlowEntra((n) => (n === 1 ? 0 : 2500));
    try {
      await withStdio({ FO_TIMEOUT_MS: "1500", FO_AUTHORITY: entra.authority }, async ({ client }) => {
        cloud.faults.metadataDelayMs = 1000; // the refused request uses up two thirds of the budget
        cloud.faults.foStatus = 401;
        const started = performance.now();
        const { text, isError } = await callToolRaw(client, "query_entity", { entity: "CustomersV3" });
        const elapsed = performance.now() - started;
        assert.equal(isError, true, text);
        assert.deepEqual(entra.grants, ["client_credentials", "client_credentials"], "the 401 leads to one fresh token request");
        assert.equal(cloud.seen.foRequests.length, 1, "the retry itself never went out");
        assert.ok(elapsed < 2000, `the call must end at its 1.5 s budget, the token request included, it took ${Math.round(elapsed)} ms and said: ${text}`);
      });
    } finally {
      await entra.close();
    }
  });

  it("describes an HTML page from a proxy by its title, for an error status and for a 200 that is not JSON", async () => {
    await withStdio({}, async ({ client }) => {
      cloud.faults.foStatus = 502;
      cloud.faults.foBody = `<!DOCTYPE html><html><head><title>502 Bad Gateway</title></head><body>${"<p>upstream</p>".repeat(500)}</body></html>`;
      const badGateway = await callToolRaw(client, "search_entities", { query: "customer" });
      assert.equal(badGateway.isError, true);
      assert.equal(badGateway.text, 'GET /Metadata/DataEntities failed with 502: HTML page "502 Bad Gateway"');
      assert.equal(cloud.seen.foRequests.length, 1, "only a 401 is retried");

      cloud.faults.foStatus = 200;
      cloud.faults.foBody = "<html><head><title>Sign in to your account</title></head><body>form</body></html>";
      const signInPage = await callToolRaw(client, "search_entities", { query: "customer" });
      assert.equal(signInPage.isError, true);
      assert.equal(signInPage.text, 'GET /Metadata/DataEntities returned something that is not JSON: HTML page "Sign in to your account"');
    });
  });

  /** GET requests of one collection under /data that the fake F&O received. */
  const dataGets = (collection) => cloud.seen.foRequests.filter((r) => r.method === "GET" && r.path.split("?")[0] === `/data/${collection}`);

  /** The audit events the server wrote to its log so far, once at least `count` of them are there. */
  async function auditEvents(log, count) {
    const deadline = Date.now() + 3000;
    for (;;) {
      const events = log().split("\n").filter((l) => l.startsWith("{")).map((l) => JSON.parse(l)).filter((e) => e.event === "tool");
      if (events.length >= count || Date.now() > deadline) return events;
      await sleep(20);
    }
  }

  it("waits out a Retry-After on a GET that fits in the budget and asks once more, as seconds or as an HTTP date", async () => {
    await withStdio({}, async ({ client }) => {
      await callTool(client, "describe_entity", { entity: "CustomersV3", fields: "account" }); // only the data request is left
      cloud.reset();
      cloud.faults.throttle = { count: 1, retryAfter: 1 };
      const started = performance.now();
      const result = await callTool(client, "query_entity", { entity: "CustomersV3", select: "CustomerAccount" });
      assert.ok(performance.now() - started >= 950, "the retry waits for Retry-After");
      assert.equal(result.returned, 3);
      assert.equal(dataGets("CustomersV3").length, 2);

      cloud.reset();
      cloud.faults.throttle = { count: 1, status: 503, retryAfter: new Date(Date.now() + 1000).toUTCString() };
      const unavailable = await callTool(client, "query_entity", { entity: "CustomersV3", select: "CustomerAccount" });
      assert.equal(unavailable.returned, 3);
      assert.equal(dataGets("CustomersV3").length, 2);
    });
  });

  it("reads a fractional Retry-After as seconds and ignores a negative one instead of taking it for a date in 2001", async () => {
    await withStdio({}, async ({ client }) => {
      await callTool(client, "describe_entity", { entity: "CustomersV3", fields: "account" });
      cloud.reset();
      cloud.faults.throttle = { count: 1, retryAfter: "1.5" };
      const started = performance.now();
      const result = await callTool(client, "query_entity", { entity: "CustomersV3", select: "CustomerAccount" });
      assert.ok(performance.now() - started >= 1450, `the retry waits 1.5 s, it took ${Math.round(performance.now() - started)} ms`);
      assert.equal(result.returned, 3);
      assert.equal(dataGets("CustomersV3").length, 2);

      for (const retryAfter of ["-5", "soon-ish 5"]) {
        cloud.reset();
        cloud.faults.throttle = { count: 1, retryAfter };
        const refused = await callToolRaw(client, "query_entity", { entity: "CustomersV3", select: "CustomerAccount" });
        assert.equal(refused.isError, true, retryAfter);
        assert.match(refused.text, /failed with 429: Too many requests, try again later\. F&O is throttling requests\. /, retryAfter);
        assert.equal(dataGets("CustomersV3").length, 1, `no retry spent on a Retry-After of ${retryAfter}`);
      }
    });
  });

  it("does not wait for a Retry-After beyond the budget, retries a GET only once and says when to try again", async () => {
    await withStdio({}, async ({ client }) => {
      cloud.faults.throttle = { count: 1, retryAfter: 120 };
      const started = performance.now();
      const far = await callToolRaw(client, "query_entity", { entity: "CustomersV3", select: "CustomerAccount" });
      assert.ok(performance.now() - started < 5000, "no wait that cannot end within the budget");
      assert.equal(far.isError, true);
      assert.equal(
        far.text,
        "GET /data/CustomersV3?$filter=dataAreaId eq 'USMF'&$select=CustomerAccount&$top=20&cross-company=true failed with 429: " +
          "Too many requests, try again later. F&O is throttling requests, retry after 120 seconds. Make fewer calls at once and wait before the next one."
      );
      assert.equal(dataGets("CustomersV3").length, 1);

      cloud.reset();
      cloud.faults.throttle = { count: 2, retryAfter: 1 };
      const twice = await callToolRaw(client, "query_entity", { entity: "CustomersV3", select: "CustomerAccount" });
      assert.equal(twice.isError, true);
      assert.match(twice.text, /failed with 429: .*retry after 1 second\./);
      assert.equal(dataGets("CustomersV3").length, 2, "one retry, not more");
    });
  });

  it("never repeats a throttled create or update and tells the model when to retry", async () => {
    await withStdio({ FO_ALLOW_WRITES: "1" }, async ({ client }) => {
      cloud.faults.throttle = { count: 1, retryAfter: 2 };
      const create = await callToolRaw(client, "create_record", { entity: "CustomerGroups", data: { CustomerGroupId: "30" } });
      assert.equal(create.isError, true);
      assert.equal(
        create.text,
        "POST /data/CustomerGroups failed with 429: Too many requests, try again later. F&O is throttling requests, retry after 2 seconds. " +
          "Make fewer calls at once and wait before the next one."
      );
      assert.equal(cloud.seen.foRequests.filter((r) => r.method === "POST" && r.path === "/data/CustomerGroups").length, 1);

      cloud.faults.throttle = { count: 1, retryAfter: 2, method: "PATCH" };
      const update = await callToolRaw(client, "update_record", { entity: "CustomerGroups", key: { CustomerGroupId: "10" }, data: { Description: "Later" } });
      assert.equal(update.isError, true);
      assert.match(update.text, /^PATCH \/data\/CustomerGroups\(dataAreaId='USMF',CustomerGroupId='10'\)\?cross-company=true failed with 429: .*retry after 2 seconds\./);
      assert.equal(cloud.seen.foRequests.filter((r) => r.method === "PATCH").length, 1);
      assert.equal(cloud.tables.CustomerGroups[0].Description, "Wholesale");
    });
  });

  it("stops waiting for Retry-After when the call is cancelled and sends no retry", async () => {
    await withStdio({}, async ({ client }) => {
      await callTool(client, "describe_entity", { entity: "CustomersV3", fields: "account" });
      cloud.reset();
      cloud.faults.throttle = { count: 1, retryAfter: 3 };
      const controller = new AbortController();
      const call = client.callTool({ name: "query_entity", arguments: { entity: "CustomersV3", select: "CustomerAccount" } }, undefined, { signal: controller.signal });
      setTimeout(() => controller.abort(), 300);
      await assert.rejects(call);
      await sleep(3500);
      assert.equal(dataGets("CustomersV3").length, 1, "the retry never went out");
    });
  });

  it("never follows a redirect from F&O, so a create body cannot be sent on to another host", async () => {
    await withStdio({ FO_ALLOW_WRITES: "1" }, async ({ client }) => {
      await callTool(client, "describe_entity", { entity: "CustomerGroups" });
      cloud.reset();
      const elsewhere = cloud.foUrl.replace("localhost", "127.0.0.1");
      cloud.faults.foStatus = 307;
      cloud.faults.foHeaders = { location: `${elsewhere}/data/Redirected` };
      const { text, isError } = await callToolRaw(client, "create_record", { entity: "CustomerGroups", data: { CustomerGroupId: "30" } });
      assert.equal(isError, true);
      assert.equal(text, `F&O answered POST /data/CustomerGroups with a redirect to ${new URL(elsewhere).host}. FO_URL is probably not the environment URL.`);
      assert.deepEqual(cloud.seen.foRequests.map((r) => `${r.method} ${r.path}`), ["POST /data/CustomerGroups"], "the redirect was not followed");
    });
  });

  it("names itself fo-mcp with its version in the User-Agent of every F&O request", async () => {
    const { version } = JSON.parse(readFileSync(join(projectDir, "package.json"), "utf8"));
    await withStdio({}, async ({ client }) => {
      await callTool(client, "describe_entity", { entity: "CustomersV3", fields: "blocked" });
      await callTool(client, "query_entity", { entity: "CustomersV3", select: "CustomerAccount" });
      const agents = [...new Set(cloud.seen.foRequests.map((r) => r.agent))];
      assert.deepEqual(agents, [`fo-mcp/${version}`]);
      assert.ok(cloud.seen.foRequests.some((r) => r.path.startsWith("/Metadata/PublicEnumerations")));
    });
  });

  it("reads a Metadata answer over 8 MB and refuses one over 20 MB", async () => {
    cloud.faults.dataEntitiesPadBytes = 9_000_000;
    await withStdio({}, async ({ client }) => {
      const found = await callTool(client, "search_entities", { query: "customer group" });
      assert.deepEqual(found.entities.map((e) => e.collection), ["CustomerGroups"]);
    });
    cloud.faults.dataEntitiesPadBytes = 21_000_000;
    await withStdio({}, async ({ client }) => {
      const { text, isError } = await callToolRaw(client, "search_entities", { query: "customer" });
      assert.equal(isError, true);
      assert.equal(text, `The answer from ${cloud.foUrl}/Metadata/DataEntities is over 20 MB.`);
    });
  });

  it("warns that a create may have gone through when the connection breaks or a gateway fails, but not for a read", async () => {
    await withStdio({ FO_ALLOW_WRITES: "1" }, async ({ client }) => {
      await callTool(client, "describe_entity", { entity: "CustomerGroups" });
      const note = "F&O may still have processed the request, so check with query_entity before repeating a create.";
      cloud.faults.dropConnections = 1;
      const dropped = await callToolRaw(client, "create_record", { entity: "CustomerGroups", data: { CustomerGroupId: "30" } });
      assert.equal(dropped.isError, true);
      assert.match(dropped.text, new RegExp(`^Request to ${escapeRegExp(cloud.foUrl)}/data/CustomerGroups failed: `));
      assert.ok(dropped.text.endsWith(` ${note}`), dropped.text);

      for (const status of [502, 503, 504]) {
        cloud.faults.foStatus = status;
        const gateway = await callToolRaw(client, "create_record", { entity: "CustomerGroups", data: { CustomerGroupId: "31" } });
        assert.equal(gateway.text, `POST /data/CustomerGroups failed with ${status}: An error has occurred. ${note}`);
      }
      cloud.faults.foStatus = 500;
      const failed = await callToolRaw(client, "create_record", { entity: "CustomerGroups", data: { CustomerGroupId: "32" } });
      assert.equal(failed.text, "POST /data/CustomerGroups failed with 500: An error has occurred.", "a 500 is an answer of F&O itself");

      cloud.reset();
      cloud.faults.dropConnections = 1;
      const read = await callToolRaw(client, "query_entity", { entity: "CustomerGroups" });
      assert.doesNotMatch(read.text, /may still have processed/);
    });
  });

  it("runs six calls of a user at once, queues the next ten within their budget and refuses a call past the queue", async () => {
    await withStdio({}, async ({ client }) => {
      await callTool(client, "query_entity", { entity: "CustomersV3", select: "CustomerAccount" }); // the metadata is cached now
      cloud.reset();
      cloud.faults.dataDelayMs = 500;
      // Claude Code sends the calls of read-only tools in parallel, a batch of eight describes or queries is common.
      const results = await Promise.all(Array.from({ length: 17 }, () => callToolRaw(client, "query_entity", { entity: "CustomersV3", select: "CustomerAccount" })));
      const refused = results.filter((r) => r.isError);
      assert.deepEqual(refused.map((r) => r.text), ["Too many tool calls at once for this user, wait for the running ones."], "only the call past the queue");
      assert.equal(results.filter((r) => !r.isError && JSON.parse(r.text).returned === 3).length, 16, "the queued calls ran once a place was free");
      assert.equal(dataGets("CustomersV3").length, 16, "the refused call never reached F&O");
      assert.equal(cloud.peakDataRequests, 6, "never more than six at once at F&O");
      cloud.faults.dataDelayMs = 0;
      const again = await callTool(client, "query_entity", { entity: "CustomersV3", select: "CustomerAccount" });
      assert.equal(again.returned, 3);
    });
  });

  it("refuses the 49th tool call on the whole server while 48 run, whoever they belong to, and takes the next once one ends", async () => {
    // Eight users with six calls each fill the server, so the ninth meets the limit of the server before the one of its own.
    // The counting is in FoShared and needs no server around it.
    const shared = new FoShared(loadConfig({ FO_URL: cloud.foUrl, FO_TENANT_ID: tenantId, FO_CLIENT_ID: clientId, FO_CLIENT_SECRET: clientSecret, FO_CA_FILE: cert.certFile }));
    const serverFull = { message: "Too many tool calls at once on this server, wait for the running ones." };
    const users = Array.from({ length: 8 }, (_, i) => `oid-user-${i}`);
    for (const user of users) for (let i = 0; i < 6; i++) await shared.enterCall(user);
    await assert.rejects(shared.enterCall("oid-user-8"), serverFull);
    await assert.rejects(shared.enterCall("oid-user-9"), serverFull);
    shared.leaveCall(users[0]);
    await shared.enterCall("oid-user-8"); // the place a call of another user left
    await assert.rejects(shared.enterCall("oid-user-9"), serverFull);
    // Everything that runs leaves, and the server takes calls again.
    const running = new Map([[users[0], 5], ...users.slice(1).map((user) => [user, 6]), ["oid-user-8", 1]]);
    for (const [user, count] of running) for (let i = 0; i < count; i++) shared.leaveCall(user);
    await shared.enterCall("oid-user-9");
    shared.leaveCall("oid-user-9");
  });

  /** The customers read of the certificate and proxy tests, with the server's log so far for what it said about the checks. */
  const customersWithLog = async ({ client, log }) => ({ ...(await callToolRaw(client, "query_entity", { entity: "CustomersV3", select: "CustomerAccount" })), log: log() });
  const INSECURE_LINE = /fo-mcp: certificate validation is disabled for localhost \(FO_INSECURE_TLS\)\. Prefer FO_CA_FILE\./;

  it("validates the F&O certificate unless FO_CA_FILE or FO_INSECURE_TLS says otherwise, and never the Entra one with FO_INSECURE_TLS", async () => {
    // The fake's own port is trusted through NODE_EXTRA_CA_CERTS, so it would pass with validation off. This one is not.
    const other = makeCert();
    try {
      const untrusted = await cloud.listenUntrusted(other.dir);
      const read = (env) => withStdio({ FO_URL: untrusted, FO_INSECURE_TLS: "", ...env }, customersWithLog);
      const certificateError = new RegExp(`^Request to ${untrusted}/Metadata/DataEntities failed: fetch failed \\((DEPTH_ZERO_SELF_SIGNED_CERT|SELF_SIGNED_CERT_IN_CHAIN)`);
      const refused = await read({});
      assert.equal(refused.isError, true, "a server that skipped the check would have read the rows");
      assert.match(refused.text, certificateError);
      assert.ok(refused.text.endsWith(" Set FO_CA_FILE to the server certificate, or FO_INSECURE_TLS=1 for a throwaway box."), refused.text);
      assert.doesNotMatch(refused.log, INSECURE_LINE);
      for (const env of [{ FO_INSECURE_TLS: "1" }, { FO_CA_FILE: other.certFile }]) {
        const { text, isError, log } = await read(env);
        assert.equal(isError, false, `${JSON.stringify(env)}: ${text}`);
        assert.equal(JSON.parse(text).returned, 3);
        if (env.FO_INSECURE_TLS) assert.match(log, INSECURE_LINE, "the server says when it skips the checks");
        else assert.doesNotMatch(log, INSECURE_LINE);
      }
      // With both set FO_CA_FILE wins and the checks stay on: the certificate of the fake's own port is the wrong one here.
      const both = await read({ FO_INSECURE_TLS: "1", FO_CA_FILE: cert.certFile });
      assert.equal(both.isError, true, "FO_INSECURE_TLS=1 next to FO_CA_FILE must not turn the checks off");
      assert.match(both.text, certificateError);
      assert.doesNotMatch(both.log, INSECURE_LINE);
      // Neither set, the default of a hosted server: the trust store plus NODE_EXTRA_CA_CERTS reach the fake's own port.
      const trusted = await withStdio({ FO_INSECURE_TLS: "" }, customersWithLog);
      assert.equal(trusted.isError, false, trusted.text);
      assert.equal(JSON.parse(trusted.text).returned, 3);
      assert.doesNotMatch(trusted.log, INSECURE_LINE);
      // FO_INSECURE_TLS is for the F&O host alone, the token request to Entra keeps checking.
      const entra = await withStdio({ FO_AUTHORITY: untrusted, FO_INSECURE_TLS: "1" }, ({ client }) => callToolRaw(client, "environment_info"));
      assert.equal(entra.isError, true, entra.text);
      assert.match(entra.text, new RegExp(`^Token request to ${untrusted}/[-0-9a-f]+/oauth2/v2\\.0/token failed: fetch failed \\(`));
    } finally {
      other.remove();
    }
  });

  /** The fake F&O under the name of the LCS one-box, which no DNS resolves. Entra issues tokens for it once a test asks. */
  const oneBoxUrl = () => `https://onebox.invalid:${new URL(cloud.foUrl).port}`;

  it("resolves the F&O host name itself with FO_HOST_IP, while the token request to Entra keeps normal DNS", async () => {
    const oneBox = oneBoxUrl();
    cloud.acceptFoOrigin(oneBox);
    const read = (env) => withStdio({ FO_URL: oneBox, FO_TIMEOUT_MS: "3000", ...env }, customersWithLog);
    const unresolved = await read({});
    assert.equal(unresolved.isError, true, "without FO_HOST_IP the name does not resolve");
    assert.match(unresolved.text, /^Request to https:\/\/onebox\.invalid:\d+\/Metadata\/DataEntities failed: /);
    assert.ok(unresolved.text.endsWith(" Set FO_HOST_IP when the F&O host name does not resolve on this machine."), unresolved.text);
    assert.deepEqual(cloud.seen.tokenGrants, ["client_credentials"], "Entra, on a name that resolves, was reached");
    assert.deepEqual(cloud.seen.foRequests, []);

    cloud.reset();
    const resolved = await read({ FO_HOST_IP: "127.0.0.1" });
    assert.equal(resolved.isError, false, resolved.text);
    assert.equal(JSON.parse(resolved.text).returned, 3);
    assert.deepEqual(cloud.seen.tokenGrants, ["client_credentials"]);
    assert.ok(cloud.seen.foRequests.length > 0, "the requests reached the fake on the fixed address");
  });

  /**
   * An HTTP proxy that only tunnels CONNECT, the way a corporate proxy serves HTTPS, on a port of its own. `targets`
   * records the host:port of every tunnel asked for. A host it cannot resolve gets 502, the one-box name's fate at a real one.
   */
  async function startProxy() {
    const targets = [];
    const sockets = new Set();
    const server = createHttpServer((req, res) => res.writeHead(405).end());
    server.on("connect", (req, socket, head) => {
      targets.push(req.url);
      const [host, port] = req.url.split(":");
      const upstream = connect({ host, port: Number(port) }, () => {
        socket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
        upstream.write(head);
        upstream.pipe(socket);
        socket.pipe(upstream);
      });
      upstream.on("error", () => socket.end("HTTP/1.1 502 Bad Gateway\r\n\r\n"));
      socket.on("error", () => upstream.destroy());
      sockets.add(upstream).add(socket);
    });
    const port = await listenOn(server);
    return {
      url: `http://127.0.0.1:${port}`,
      targets,
      close: () => new Promise((resolve) => {
        for (const s of sockets) s.destroy();
        server.close(resolve);
      }),
    };
  }

  it("reaches Entra and F&O through HTTPS_PROXY with a CONNECT tunnel, and with FO_HOST_IP the F&O host alone goes past the proxy", async () => {
    const proxy = await startProxy();
    try {
      // serverEnv blanks both spellings, and undici reads the lowercase one first.
      const viaProxy = { HTTPS_PROXY: proxy.url, https_proxy: proxy.url };
      const fakeHost = new URL(cloud.origin).host;
      const proxied = await withStdio(viaProxy, customersWithLog);
      assert.equal(proxied.isError, false, proxied.text);
      assert.equal(JSON.parse(proxied.text).returned, 3);
      assert.deepEqual([...new Set(proxy.targets)], [fakeHost], "Entra and F&O were reached through the tunnel");
      assert.ok(proxy.targets.length >= 2, `a tunnel for Entra and one for F&O at least, got ${proxy.targets.length}`);
      assert.ok(cloud.seen.foRequests.length > 0);

      // The one-box name only FO_HOST_IP resolves. A proxy cannot, so the F&O host bypasses it, and Entra still goes through it.
      proxy.targets.length = 0;
      cloud.reset();
      const oneBox = oneBoxUrl();
      cloud.acceptFoOrigin(oneBox);
      const direct = await withStdio({ ...viaProxy, FO_URL: oneBox, FO_HOST_IP: "127.0.0.1" }, customersWithLog);
      assert.equal(direct.isError, false, direct.text);
      assert.equal(JSON.parse(direct.text).returned, 3);
      assert.deepEqual([...new Set(proxy.targets)], [fakeHost], "only Entra went through the proxy");
      assert.deepEqual(cloud.seen.tokenGrants, ["client_credentials"]);
      assert.ok(cloud.seen.foRequests.length > 0, "F&O was reached on the fixed address");
    } finally {
      await proxy.close();
    }
  });

  it("writes one audit line per call to stderr, without filters or values, and none with FO_AUDIT=0", async () => {
    await withStdio({ FO_ALLOW_WRITES: "1" }, async ({ client, log }) => {
      await callTool(client, "query_entity", { entity: "customersv3", select: "CustomerAccount", filter: "OrganizationName eq 'Contoso Retail San Diego'" });
      await callToolRaw(client, "query_entity", { entity: "CustomersV3", filter: "OrganizationName eq 'Secret Name'", select: "Nope,*" });
      // A model often writes a long filter on two lines. The line break must not keep the query string in the log.
      await callToolRaw(client, "query_entity", { entity: "CustomersV3", filter: "CreditLimit gt 4711\nor CreditLimit lt 12", select: "Nope,*" });
      // The filter stays out of the log, so the company a dataAreaId filter reads is named in the company field instead.
      await callTool(client, "query_entity", { entity: "CustomersV3", select: "CustomerAccount", filter: "dataAreaId eq 'DEMF' and OrganizationName eq 'Contoso Europe'" });
      await callTool(client, "update_record", { entity: "CustomerGroups", key: { CustomerGroupId: "10" }, data: { Description: "Changed secret" } });
      const events = await auditEvents(log, 5);
      assert.deepEqual(events.map((e) => [e.tool, e.entity, e.company, e.user, e.ok]), [
        ["query_entity", "CustomersV3", "USMF", "service", true],
        ["query_entity", "CustomersV3", "USMF", "service", false],
        ["query_entity", "CustomersV3", "USMF", "service", false],
        ["query_entity", "CustomersV3", "(from filter: DEMF)", "service", true],
        ["update_record", "CustomerGroups", "USMF", "service", true],
      ]);
      assert.equal(events[1].error, "GET /data/CustomersV3?... failed with 400: Could not find a property named '...' on type '...'.");
      assert.equal(events[2].error, events[1].error);
      assert.deepEqual([events[4].key, events[4].fields], [{ CustomerGroupId: "10", dataAreaId: "USMF" }, ["Description"]]);
      assert.equal("before" in events[4], false, "values only with FO_AUDIT_VALUES=1");
      assert.doesNotMatch(log(), /Contoso Europe/, "the rest of the filter stays out of the log");
      assert.doesNotMatch(log(), /Contoso Retail San Diego|Secret Name|Changed secret|Wholesale|gt 4711|CreditLimit/);
      assert.doesNotMatch(log(), /fo-token-for/);
    });
    await withStdio({ FO_AUDIT: "0" }, async ({ client, log }) => {
      await callTool(client, "environment_info");
      await sleep(200);
      assert.deepEqual(await auditEvents(log, 0), []);
    });
  });

  it("audits a remote call with the signed in user, the client and the session, and shares labels and enums between users", async () => {
    const server = await startServer({ cloud, certFile: cert.certFile });
    try {
      const alice = await connectWithSignIn(server.url, makeProvider(cloud, "alice"));
      const bob = await connectWithSignIn(server.url, makeProvider(cloud, "bob"));
      try {
        await callTool(alice, "describe_entity", { entity: "CustomersV3" });
        const [event] = await auditEvents(server.log, 1);
        assert.deepEqual(
          [event.tool, event.entity, event.user, event.oid, event.ok],
          ["describe_entity", "CustomersV3", "alice@example.com", "oid-alice", true]
        );
        assert.equal(typeof event.client, "string");
        assert.ok(event.client.length > 0);
        assert.equal(event.session, alice.transportInUse.sessionId);

        // Labels and enums are not secured in F&O, so Bob gets them from what Alice loaded. Entity metadata stays per user.
        cloud.reset();
        const described = await callTool(bob, "describe_entity", { entity: "CustomersV3" });
        assert.equal(described.fields.find((f) => f.name === "Blocked").values.length, 6);
        assert.equal(described.label, "CustomerV3 (en-US)");
        assert.deepEqual(
          cloud.seen.foRequests.map((r) => `${r.user} ${r.path.split("?")[0]}`).sort(),
          ["bob@example.com /Metadata/DataEntities", "bob@example.com /Metadata/PublicEntities"]
        );
      } finally {
        await alice.close();
        await bob.close();
      }
    } finally {
      await server.stop();
    }
  });

  it("exits at start with a readable message on stderr for invalid configuration values", async () => {
    const certFile = cert.certFile;
    const cases = [
      ["dist/index.js", { FO_TIMEOUT_MS: "abc" }, "FO_TIMEOUT_MS must be a whole number of milliseconds between 1000 and 60000, got 'abc'"],
      ["dist/index.js", { FO_TIMEOUT_MS: "999" }, "FO_TIMEOUT_MS must be a whole number of milliseconds between 1000 and 60000, got '999'"],
      ["dist/index.js", { FO_TIMEOUT_MS: "60001" }, "FO_TIMEOUT_MS must be a whole number of milliseconds between 1000 and 60000, got '60001'"],
      ["dist/index.js", { FO_TIMEOUT_MS: "1500.5" }, "FO_TIMEOUT_MS must be a whole number of milliseconds between 1000 and 60000, got '1500.5'"],
      ["dist/index.js", { FO_URL: "not a url" }, "FO_URL must look like https://host, got 'not a url'"],
      ["dist/index.js", { FO_URL: "http://fo.example.com" }, "FO_URL must look like https://host, got 'http://fo.example.com'"],
      ["dist/index.js", { FO_URL: "https://fo.example.com/namespaces/AXSF" }, "FO_URL must look like https://host, got 'https://fo.example.com/namespaces/AXSF'"],
      ["dist/index.js", { FO_AUTHORITY: "http://login.example.com" }, "FO_AUTHORITY must start with https://, got 'http://login.example.com'"],
      ["dist/index.js", { FO_HOST_IP: "10.0.0" }, "FO_HOST_IP must be an IPv4 or IPv6 address without brackets, got '10.0.0'"],
      ["dist/index.js", { FO_ALLOW_WRITES: "maybe" }, "FO_ALLOW_WRITES must be 1 or 0, got 'maybe'"],
      ["dist/index.js", { FO_CLIENT_ID: "" }, "Missing environment variable FO_CLIENT_ID. Copy .env.example to .env and fill in the values."],
      ["dist/index.js", { FO_CA_FILE: "no-such-file.pem" }, `Cannot read FO_CA_FILE ${join(projectDir, "no-such-file.pem")}: ENOENT`],
      ["dist/index.js", { FO_ENTITIES: "CustomerGroups", FO_WRITE_ENTITIES: "customergroups,CustomersV3" },
        "Every entity in FO_WRITE_ENTITIES must be on FO_ENTITIES too, missing there: CustomersV3"],
      ["dist/index.js", { FO_AUDIT: "maybe" }, "FO_AUDIT must be 1 or 0, got 'maybe'"],
      ["dist/index.js", { FO_AUDIT_VALUES: "all" }, "FO_AUDIT_VALUES must be 1 or 0, got 'all'"],
      ["dist/http.js", { FO_TIMEOUT_MS: "abc", MCP_PORT: "1" }, "FO_TIMEOUT_MS must be a whole number of milliseconds between 1000 and 60000, got 'abc'"],
    ];
    const results = await Promise.all(cases.map(([script, env]) => runScript(script, serverEnv(cloud, certFile, env))));
    cases.forEach(([script, env, message], i) => {
      const { code, stdout, stderr } = results[i];
      const label = `${script} with ${JSON.stringify(env)}`;
      assert.equal(code, 1, `${label} must exit with code 1, stderr: ${stderr}`);
      assert.ok(stderr.includes(`fo-mcp: ${message}`), `${label} must say "${message}", stderr was: ${stderr}`);
      assert.doesNotMatch(stderr, /\n\s+at /, `${label} must not print a stack trace`);
      assert.equal(stdout, "", `${label} must write nothing to stdout, the MCP channel`);
    });
    assert.deepEqual(cloud.seen.tokenGrants, [], "a server with invalid configuration never asks Entra for a token");
  });

  it("warns at start when NODE_TLS_REJECT_UNAUTHORIZED=0 turns off certificate checks for every host", async () => {
    const [insecure, normal] = await Promise.all(
      ["0", ""].map((value) => runScript("dist/index.js", serverEnv(cloud, cert.certFile, { NODE_TLS_REJECT_UNAUTHORIZED: value }), { readyLine: "ready for" }))
    );
    assert.equal(insecure.ready, true, insecure.stderr);
    assert.ok(
      insecure.stderr.includes(
        "fo-mcp: NODE_TLS_REJECT_UNAUTHORIZED=0 turns off certificate validation for every connection, Entra included. " +
          "Remove it and set FO_CA_FILE, or FO_INSECURE_TLS=1 for the F&O host alone."
      ),
      insecure.stderr
    );
    assert.equal(normal.ready, true, normal.stderr);
    assert.doesNotMatch(normal.stderr, /NODE_TLS_REJECT_UNAUTHORIZED/);
  });

  it("starts with FO_TIMEOUT_MS at its bounds 1000 and 60000 and with spaces around a valid value", async () => {
    const results = await Promise.all(
      ["1000", "60000", " 2000 "].map((value) => runScript("dist/index.js", serverEnv(cloud, cert.certFile, { FO_TIMEOUT_MS: value }), { readyLine: "ready for" }))
    );
    for (const { ready, stderr } of results) assert.equal(ready, true, stderr);
  });
});
