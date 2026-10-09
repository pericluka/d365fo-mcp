// Tests of the OAuth front of the remote server (src/oauth.ts and the token checks in src/http.ts): signed client
// registration, /authorize with the consent page, the browser binding at /callback, /token, /revoke, the metadata
// documents and tokens that come straight from Entra. dist/http.js runs as a child process against the fake Entra and
// fake F&O of test/support.mjs. Run with node --test test/oauth.test.mjs
import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import { after, before, beforeEach, describe, it } from "node:test";
import {
  assertPage, authorizeInBrowser, clientId, clientRedirect, connectWithSignIn, consentForm, ENTRA_TRACE, INITIALIZE, logLine, makeBrowser,
  makeCert, makeProvider, mcpPost, NO_OPENSSL, postConsent, random, randomIp, refreshAt, registerClient, s256, startFakeCloud, startServer, SUITE_TIMEOUT, tenantId,
} from "./support.mjs";

const SCOPE = `api://${clientId}/access_as_user`;
const CLAUDE_CALLBACK = "https://claude.ai/api/mcp/auth_callback";
const OTHER_APP = "99999999-8888-7777-6666-555555555555";

/**
 * Parse a Bearer challenge strictly by RFC 7235: auth-params of the form name=token or name="quoted string", with
 * a double quote inside a quoted string escaped as \". Returns undefined when the header is not well formed.
 */
function parseChallenge(header) {
  const start = /^Bearer +/.exec(header ?? "");
  if (!start) return undefined;
  const tchar = "[!#$%&'*+.^_`|~0-9A-Za-z-]";
  const param = new RegExp(`(${tchar}+)[ \\t]*=[ \\t]*(?:"((?:[^"\\\\]|\\\\.)*)"|(${tchar}+))[ \\t]*(,[ \\t]*|$)`, "y");
  param.lastIndex = start[0].length;
  const params = {};
  while (param.lastIndex < header.length) {
    const m = param.exec(header);
    if (!m) return undefined;
    params[m[1]] = m[2] !== undefined ? m[2].replace(/\\(.)/g, "$1") : m[3];
    if (m[4] === "") break;
  }
  return param.lastIndex === header.length ? params : undefined;
}

/** The registration a client id carries, decoded the way anyone can: it is signed, not secret. */
const registrationOf = (id) => JSON.parse(Buffer.from(id.split(".")[1], "base64url").toString("utf8"));

describe("OAuth front of the remote server", { timeout: SUITE_TIMEOUT, skip: NO_OPENSSL }, () => {
  let cert, cloud, server, port, base, serverUrl;
  /** The browser most tests sign in with. It approved testClient once, so /authorize sends it straight to Entra. */
  let browser;
  /** A registered client with the test redirect URI and the claude.ai callback, and a second one with the test redirect URI. */
  let testClient, otherClient;

  before(async () => {
    cert = makeCert();
    cloud = await startFakeCloud(cert.dir);
    server = await startServer({ cloud, certFile: cert.certFile });
    ({ port } = server);
    base = `http://localhost:${port}`;
    serverUrl = server.url;
    testClient = await registerClient(base, { redirectUris: [clientRedirect, CLAUDE_CALLBACK], name: "oauth test" });
    otherClient = await registerClient(base, { name: "another client" });
    browser = makeBrowser();
    const approved = await authorizeInBrowser(browser, authorizeUrl(authorizeParams().params));
    assert.equal(approved.status, 303, "the test browser approves the test client once");
  });

  after(async () => {
    await server?.stop();
    await cloud?.close();
    cert?.remove();
  });

  beforeEach(() => cloud.reset());

  // ------------------------------------------------------------ helpers

  const register = (body, headers = { "content-type": "application/json" }) =>
    fetch(`${base}/register`, { method: "POST", headers: { "x-forwarded-for": randomIp(), ...headers }, body: body === undefined ? undefined : typeof body === "string" ? body : JSON.stringify(body) });

  /** A valid authorize request of a client, with any parameter replaced or removed (undefined removes it). */
  function authorizeParams(overrides = {}) {
    const verifier = random() + random();
    const params = { client_id: testClient, redirect_uri: clientRedirect, response_type: "code", code_challenge: s256(verifier), code_challenge_method: "S256", state: random(), ...overrides };
    for (const k of Object.keys(params)) if (params[k] === undefined) delete params[k];
    return { params, verifier };
  }

  const authorizeUrl = (params, at = base) => `${at}/authorize?${new URLSearchParams(params)}`;
  const authorize = (params) => browser.fetch(authorizeUrl(params));

  /** The client redirect an authorization response lands on, checked to be the client's own redirect URI and to name the issuer. */
  async function clientRedirectOf(response, redirectUri = clientRedirect) {
    assert.ok([302, 303].includes(response.status), `expected a redirect, got ${response.status} ${await response.clone().text()}`);
    const back = new URL(response.headers.get("location"));
    assert.equal(`${back.origin}${back.pathname}`, redirectUri, "the answer goes back to the client's redirect URI");
    assert.equal(back.searchParams.get("iss"), base, "every authorization response names the issuer (RFC 9207)");
    return back;
  }

  /** The client redirect an /authorize error lands on. */
  async function errorRedirect(response, redirectUri = clientRedirect) {
    const back = await clientRedirectOf(response, redirectUri);
    assert.equal(back.searchParams.get("code"), null, "an error redirect carries no code");
    return back;
  }

  /** The Entra authorize URL a response sends the browser to. */
  function entraOf(response) {
    assert.ok([302, 303].includes(response.status), `expected a redirect to Entra, got ${response.status}`);
    const entra = new URL(response.headers.get("location"));
    assert.equal(`${entra.origin}${entra.pathname}`, `${cloud.origin}/${tenantId}/oauth2/v2.0/authorize`);
    return entra;
  }

  /** The full sign in with the browser replaced by fetches: /authorize, the consent page, the fake Entra, /callback. Returns the client's code. */
  async function signIn({ user = "alice", client = testClient, redirectUri = clientRedirect, as = browser, scope } = {}) {
    const { params, verifier } = authorizeParams({ client_id: client, redirect_uri: redirectUri, scope });
    const toCallback = cloud.authorize(entraOf(await authorizeInBrowser(as, authorizeUrl(params))).searchParams, user);
    const back = await clientRedirectOf(await as.fetch(toCallback), redirectUri);
    assert.equal(back.searchParams.get("error"), null, back.searchParams.get("error_description") ?? "");
    assert.equal(back.searchParams.get("state"), params.state);
    return { code: back.searchParams.get("code"), verifier, client, redirectUri, state: params.state };
  }

  /** A form POST to /token. A field set to undefined is left out. */
  const tokenForm = (fields) => {
    const body = new URLSearchParams(Object.entries(fields).filter(([, v]) => v !== undefined));
    return fetch(`${base}/token`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded", "x-forwarded-for": randomIp() }, body });
  };
  const tokenJson = (body) => fetch(`${base}/token`, { method: "POST", headers: { "content-type": "application/json", "x-forwarded-for": randomIp() }, body: JSON.stringify(body) });
  const exchange = (s, overrides = {}) =>
    tokenForm({ grant_type: "authorization_code", code: s.code, client_id: s.client, redirect_uri: s.redirectUri, code_verifier: s.verifier, ...overrides });
  const revoke = (fields) =>
    fetch(`${base}/revoke`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded", "x-forwarded-for": randomIp() }, body: new URLSearchParams(fields) });

  /** An error answer with an OAuth error body (JSON with the given error code), never a 500 or an HTML page. */
  async function assertOAuthError(response, error, status = 400) {
    const text = await response.text();
    assert.equal(response.status, status, text);
    assert.match(response.headers.get("content-type") ?? "", /application\/json/, text);
    const body = JSON.parse(text);
    assert.equal(body.error, error, text);
    return body;
  }

  /** A 401 from /mcp with a Bearer challenge that points at the protected resource metadata. */
  async function assertUnauthorized(response) {
    assert.equal(response.status, 401, await response.clone().text());
    const header = response.headers.get("www-authenticate");
    assert.match(header ?? "", /^Bearer /, "the 401 needs a Bearer challenge");
    assert.match(header, /error="invalid_token"/);
    assert.equal(/resource_metadata="([^"]+)"/.exec(header)?.[1], `${base}/.well-known/oauth-protected-resource/mcp`);
    return header;
  }

  /** Run a second server against the same fake cloud for the length of one test. */
  async function withServer(env, run) {
    const other = await startServer({ cloud, certFile: cert.certFile, env });
    try {
      return await run({ base: `http://localhost:${other.port}`, url: other.url, server: other });
    } finally {
      await other.stop();
    }
  }

  // ------------------------------------------------------------ /register

  it("refuses to register redirect URIs outside localhost and the Claude callbacks", async () => {
    const refused = [
      "https://evil.example/callback",
      "http://localhost.evil.example/callback",
      "http://localhost@evil.example/callback",
      "http://evil.example@localhost/callback",
      "http://localhost:8787/callback#fragment",
      "https://claude.ai/api/mcp/other_callback",
      "http://claude.ai/api/mcp/auth_callback",
      "https://claude.ai/api/mcp/auth_callback/",
      "https://claude.ai.evil.example/api/mcp/auth_callback",
      "https://evil.example/?next=https://claude.ai/api/mcp/auth_callback",
      "ftp://localhost/callback",
      "javascript:alert(1)//localhost",
      "not a url",
    ];
    for (const uri of refused) {
      const r = await register({ redirect_uris: [uri] });
      assert.equal(r.status, 400, `${uri} must be refused`);
      assert.equal((await r.json()).error, "invalid_redirect_uri", uri);
    }
    const mixed = await register({ redirect_uris: [clientRedirect, "https://evil.example/callback"] });
    assert.equal(mixed.status, 400, "one bad URI among good ones refuses the registration");
    assert.equal((await mixed.json()).error, "invalid_redirect_uri");
  });

  it("refuses a registration without redirect_uris or with redirect_uris that is not an array of strings", async () => {
    const bodies = [{}, { redirect_uris: clientRedirect }, { redirect_uris: { 0: clientRedirect } }, { redirect_uris: null }, { redirect_uris: [] }, { redirect_uris: [42] }, { redirect_uris: [[clientRedirect]] }];
    for (const body of bodies) {
      const r = await register(body);
      assert.equal(r.status, 400, JSON.stringify(body));
      assert.equal((await r.json()).error, "invalid_redirect_uri", JSON.stringify(body));
    }
    const empty = await register(undefined, {});
    assert.equal(empty.status, 400, "a request without a body is refused too");
    assert.equal((await empty.json()).error, "invalid_redirect_uri");
  });

  it("registers a public client with a signed client id that carries the registration, and stores nothing", async () => {
    const before = Math.floor(Date.now() / 1000);
    const r = await register({ client_name: "Claude", redirect_uris: [CLAUDE_CALLBACK] });
    assert.equal(r.status, 201);
    const client = await r.json();
    assert.match(client.client_id, /^dyn\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{43}$/);
    const registration = registrationOf(client.client_id);
    assert.deepEqual({ ...registration, t: undefined }, { v: 1, n: "Claude", r: [CLAUDE_CALLBACK], t: undefined });
    assert.ok(registration.t >= before && registration.t <= Math.floor(Date.now() / 1000) + 1, `issued at ${registration.t}`);
    assert.equal(client.client_id_issued_at, registration.t);
    assert.deepEqual(client.redirect_uris, [CLAUDE_CALLBACK]);
    assert.equal(client.client_name, "Claude");
    assert.equal(client.token_endpoint_auth_method, "none");
    assert.deepEqual(client.grant_types, ["authorization_code", "refresh_token"]);
    assert.deepEqual(client.response_types, ["code"]);
    assert.equal(client.client_secret, undefined, "a public client gets no secret");
    const unnamed = await (await register({ redirect_uris: [CLAUDE_CALLBACK] })).json();
    assert.notEqual(unnamed.client_id, client.client_id, "another registration gets another client id");
    assert.equal(unnamed.client_name, "MCP client");
    assert.equal(registrationOf(unnamed.client_id).n, undefined);

    for (const uri of ["https://claude.com/api/mcp/auth_callback", "http://127.0.0.1:33418/callback", "http://[::1]:33418/callback", "https://localhost:8443/cb", clientRedirect]) {
      const ok = await register({ redirect_uris: [uri] });
      assert.equal(ok.status, 201, `${uri} must be accepted`);
    }
  });

  it("refuses a client_name that is not up to 100 printable characters and a registration too large for a client id", async () => {
    for (const client_name of ["x".repeat(101), "line\nbreak", "tab\there", "‮evil", "zero​width", 42, ["Claude"]]) {
      const r = await register({ client_name, redirect_uris: [clientRedirect] });
      assert.equal(r.status, 400, JSON.stringify(client_name));
      assert.equal((await r.json()).error, "invalid_client_metadata", JSON.stringify(client_name));
    }
    for (const client_name of ["x".repeat(100), "Čađavi Šljunak 東京", null, ""]) {
      assert.equal((await register({ client_name, redirect_uris: [clientRedirect] })).status, 201, JSON.stringify(client_name));
    }
    const many = Array.from({ length: 30 }, (_, i) => `http://localhost:${9000 + i}/a/rather/long/callback/path/for/one/native/client`);
    const tooLarge = await register({ redirect_uris: many });
    assert.equal(tooLarge.status, 400);
    assert.equal((await tooLarge.json()).error, "invalid_client_metadata");
  });

  it("keeps registrations valid across a restart, and another MCP_STATE_KEY makes them unknown", async () => {
    const { params } = authorizeParams();
    await withServer({}, async (restarted) => {
      // A server with the same client secret knows the client.
      consentForm(await assertPage(await makeBrowser().fetch(authorizeUrl(params, restarted.base)), 200));
    });
    await withServer({ MCP_STATE_KEY: "k".repeat(32) }, async (rekeyed) => {
      await assertPage(await makeBrowser().fetch(authorizeUrl(params, rekeyed.base)), 400, /Remove the connector/);
      const own = await registerClient(rekeyed.base);
      consentForm(await assertPage(await makeBrowser().fetch(authorizeUrl({ ...params, client_id: own }, rekeyed.base)), 200));
      await assertPage(await makeBrowser().fetch(authorizeUrl({ ...params, client_id: own })), 400, /Remove the connector/);
    });
  });

  // ------------------------------------------------------------ /authorize

  it("answers /authorize with a 400 page and no redirect for a redirect_uri outside the allowlist or a missing client_id", async () => {
    const cases = [
      { redirect_uri: "https://evil.example/callback" },
      { redirect_uri: "https://claude.ai/api/mcp/auth_callback/../../evil" },
      { redirect_uri: "http://localhost@evil.example/callback" },
      { redirect_uri: undefined },
      { client_id: undefined },
      { client_id: "" },
    ];
    for (const overrides of cases) await assertPage(await authorize(authorizeParams(overrides).params), 400);
    assert.equal(cloud.seen.authorizeRequests.length, 0);
  });

  it("answers a forged, altered, old style or unknown client id with a page that says to add the connector again, and /token with invalid_client", async () => {
    const [, payload, mac] = testClient.split(".");
    const otherPayload = otherClient.split(".")[1];
    const foreignMac = createHmac("sha256", "another key").update(`client\n${payload}`).digest("base64url");
    const forged = {
      "old style": `dyn-${random()}`,
      "altered signature": `dyn.${payload}.${mac.slice(0, -1)}${mac.endsWith("A") ? "B" : "A"}`,
      "altered registration": `dyn.${otherPayload}.${mac}`,
      "another key": `dyn.${payload}.${foreignMac}`,
      "unsigned": `dyn.${Buffer.from(JSON.stringify({ v: 1, r: [clientRedirect], t: 1 })).toString("base64url")}.${"A".repeat(43)}`,
      "garbage": "dyn.%%%.x",
    };
    for (const [name, id] of Object.entries(forged)) {
      const html = await assertPage(await authorize(authorizeParams({ client_id: id }).params), 400, /Remove the connector in your MCP client, add it again/);
      assert.ok(!html.includes(id), `${name}: the page does not echo the client id`);
      const refresh = await tokenForm({ grant_type: "refresh_token", refresh_token: "x", client_id: id });
      await assertOAuthError(refresh, "invalid_client", 401);
    }
    assert.equal(cloud.seen.authorizeRequests.length, 0);
    assert.deepEqual(cloud.seen.tokenGrants, [], "nothing reaches Entra for an unknown client");
  });

  it("accepts only a redirect URI the client registered, a loopback one on any port", async () => {
    const native = await registerClient(base, { redirectUris: ["http://127.0.0.1:33418/callback", "http://[::1]:33418/cb", "http://localhost:7000/cb?app=1"] });
    const claude = await registerClient(base, { redirectUris: [CLAUDE_CALLBACK] });
    const accepted = ["http://127.0.0.1:33418/callback", "http://127.0.0.1:50123/callback", "http://[::1]:9/cb", "http://localhost/cb?app=1", "http://localhost:7001/cb?app=1"];
    for (const uri of accepted) consentForm(await assertPage(await makeBrowser().fetch(authorizeUrl(authorizeParams({ client_id: native, redirect_uri: uri }).params)), 200));
    const refused = [
      [native, "http://127.0.0.1:50123/other"],
      [native, "https://127.0.0.1:33418/callback"],
      [native, "http://localhost:33418/callback"],
      [native, "http://localhost:7000/cb"],
      [native, "http://localhost:7000/cb?app=2"],
      [native, CLAUDE_CALLBACK],
      [claude, "https://claude.com/api/mcp/auth_callback"],
      [claude, clientRedirect],
    ];
    for (const [client, uri] of refused) {
      await assertPage(await makeBrowser().fetch(authorizeUrl(authorizeParams({ client_id: client, redirect_uri: uri }).params)), 400, /redirect_uri/);
    }
    assert.equal(cloud.seen.authorizeRequests.length, 0);

    // A sign in on another loopback port works, and the code is bound to the port the client used.
    const s = await signIn({ client: native, redirectUri: "http://127.0.0.1:50123/callback", as: makeBrowser() });
    await assertOAuthError(await exchange(s, { redirect_uri: "http://127.0.0.1:33418/callback" }), "invalid_grant");
    const t = await signIn({ client: native, redirectUri: "http://127.0.0.1:50124/callback", as: makeBrowser() });
    assert.equal((await exchange(t)).status, 200);
  });

  it("answers /authorize with 414 for a request URL over 4096 characters and accepts one of exactly 4096", async () => {
    // Unknown parameters are ignored (RFC 6749 section 3.1), so one of them fills the URL.
    const { params } = authorizeParams({ pad: "" });
    const bare = `/authorize?${new URLSearchParams(params)}`;
    const atLimit = { ...params, pad: "a".repeat(4096 - bare.length) };
    assert.equal(`/authorize?${new URLSearchParams(atLimit)}`.length, 4096);
    entraOf(await authorize(atLimit));

    await assertPage(await authorize({ ...params, pad: "a".repeat(4097 - bare.length) }), 414);
    await assertPage(await authorize({ ...params, pad: "a".repeat(6000) }), 414);
  });

  it("carries a client state of up to 1024 characters through Entra, keeps the Entra URL under 4096 characters with the largest client id and refuses a longer state", async () => {
    // The longest redirect URI a client id of at most 1500 characters can carry, registered without a name.
    const registerUri = (uri) => fetch(`${base}/register`, { method: "POST", headers: { "content-type": "application/json", "x-forwarded-for": randomIp() }, body: JSON.stringify({ redirect_uris: [uri] }) });
    const path = (n) => `http://127.0.0.1/${"p".repeat(n)}`;
    let n = 1000;
    while ((await registerUri(path(n + 1))).status === 201) n++;
    const r = await registerUri(path(n));
    assert.equal(r.status, 201);
    const client = (await r.json()).client_id;
    assert.ok(client.length > 1450 && client.length <= 1500, `client id of ${client.length} characters`);
    // A loopback redirect may use any port, which makes it longer than the registered one.
    const redirectUri = `http://127.0.0.1:65535/${"p".repeat(n)}`;
    const state = `${'"\\'.repeat(100)}${"s".repeat(1024 - 400)}`;
    assert.equal(Buffer.byteLength(JSON.stringify(state)) - 2, 1024, "the state takes all 1024 bytes once its quotes and backslashes are escaped");

    const { params, verifier } = authorizeParams({ client_id: client, redirect_uri: redirectUri, state });
    assert.ok(authorizeUrl(params).length - base.length <= 4096, "the authorize request itself is legal");
    const as = makeBrowser();
    const entra = entraOf(await authorizeInBrowser(as, authorizeUrl(params)));
    // The fake Entra has a short host. login.microsoftonline.com and a real server origin add about 100 characters.
    assert.ok(entra.href.length < 4096 - 200, `the Entra URL has ${entra.href.length} characters`);
    assert.equal(entra.href.includes("ppppp"), false, "the sealed state hides the redirect URI");
    const back = await clientRedirectOf(await as.fetch(cloud.authorize(entra.searchParams, "alice")), redirectUri);
    assert.equal(back.searchParams.get("state"), state, "the state comes back unchanged");
    assert.equal((await exchange({ code: back.searchParams.get("code"), verifier, client, redirectUri })).status, 200);

    const tooLong = authorizeParams({ state: "s".repeat(1025) }).params;
    const refused = await errorRedirect(await authorize(tooLong));
    assert.equal(refused.searchParams.get("error"), "invalid_request");
    assert.match(refused.searchParams.get("error_description"), /state may be at most 1024 characters/);
    const escaped = await errorRedirect(await authorize(authorizeParams({ state: '"'.repeat(513) }).params));
    assert.equal(escaped.searchParams.get("error"), "invalid_request", "513 quotes take 1026 bytes once escaped");
  });

  it("redirects back with invalid_request, the state and iss for a code_challenge that is not 43 base64url characters or not S256", async () => {
    const valid = s256("some verifier");
    const cases = [
      { code_challenge: "x" },
      { code_challenge: valid.slice(0, 42) },
      { code_challenge: `${valid}a` },
      { code_challenge: `${valid.slice(0, 42)}+` },
      { code_challenge: `${valid.slice(0, 42)}=` },
      { code_challenge: `${valid.slice(0, 42)}/` },
      { code_challenge: undefined },
      { code_challenge_method: "plain" },
      { code_challenge_method: "plain", code_challenge: random() + random() },
      { code_challenge_method: "s256" },
      { code_challenge_method: undefined },
    ];
    for (const overrides of cases) {
      const { params } = authorizeParams(overrides);
      const back = await errorRedirect(await authorize(params));
      assert.equal(back.searchParams.get("error"), "invalid_request", JSON.stringify(overrides));
      assert.equal(back.searchParams.get("state"), params.state, `state must come back for ${JSON.stringify(overrides)}`);
    }
    assert.equal(cloud.seen.authorizeRequests.length, 0);
  });

  it("redirects back with unsupported_response_type and the state for response_type token", async () => {
    const { params } = authorizeParams({ response_type: "token" });
    const back = await errorRedirect(await authorize(params));
    assert.equal(back.searchParams.get("error"), "unsupported_response_type");
    assert.equal(back.searchParams.get("state"), params.state);

    // The same error at a claude.ai callback goes to claude.ai, and a request without state gets no state back.
    const claude = authorizeParams({ response_type: "token", redirect_uri: CLAUDE_CALLBACK, state: undefined }).params;
    const toClaude = await errorRedirect(await authorize(claude), CLAUDE_CALLBACK);
    assert.equal(toClaude.searchParams.get("error"), "unsupported_response_type");
    assert.equal(toClaude.searchParams.has("state"), false);
  });

  it("accepts the configured scope with the OpenID scopes or none at all, refuses any other with invalid_scope and always issues the configured one", async () => {
    for (const scope of ["", SCOPE, `openid profile offline_access email ${SCOPE}`, "openid", "offline_access"]) {
      entraOf(await authorize(authorizeParams({ scope }).params));
    }
    for (const scope of ["User.Read", `${SCOPE} User.Read`, "api://other/access_as_user", `${SCOPE}/`]) {
      const { params } = authorizeParams({ scope });
      const back = await errorRedirect(await authorize(params));
      assert.equal(back.searchParams.get("error"), "invalid_scope", scope);
      assert.equal(back.searchParams.get("state"), params.state);
    }
    const s = await signIn({ scope: "openid offline_access" });
    const t = await (await exchange(s)).json();
    assert.equal(t.scope, SCOPE, "the issued scope is the configured one");
  });

  it("sends a valid authorize request to Entra with the server's own client id, its own PKCE challenge and its own /callback", async () => {
    const { params } = authorizeParams();
    const entra = entraOf(await authorize(params));
    const q = entra.searchParams;
    assert.equal(q.get("client_id"), clientId, "Entra sees the server's app registration, not the MCP client");
    assert.equal(q.get("response_type"), "code");
    assert.equal(q.get("redirect_uri"), `${base}/callback`);
    assert.equal(q.get("response_mode"), "query");
    assert.equal(q.get("scope"), `${clientId}/access_as_user openid profile offline_access`);
    assert.equal(q.get("code_challenge_method"), "S256");
    assert.match(q.get("code_challenge"), /^[A-Za-z0-9_-]{43}$/);
    assert.notEqual(q.get("code_challenge"), params.code_challenge, "the server runs its own PKCE towards Entra");
    assert.ok(q.get("state"), "the server keeps the sign in under its own state");
    assert.notEqual(q.get("state"), params.state, "the client's state is not handed to Entra");
    assert.equal(entra.href.includes(testClient.split(".")[2]), false, "the MCP client id never reaches Entra");
    assert.equal(entra.href.includes(encodeURIComponent(clientRedirect)), false, "the client's redirect URI never reaches Entra");
  });

  // ------------------------------------------------------------ consent page

  it("shows a consent page for a client this browser has not approved, with safe headers, the escaped name and where the result goes", async () => {
    const hostile = await registerClient(base, { redirectUris: [CLAUDE_CALLBACK], name: `<script>alert("x")</script> & 'Co'` });
    const fresh = makeBrowser();
    const r = await fresh.fetch(authorizeUrl(authorizeParams({ client_id: hostile, redirect_uri: CLAUDE_CALLBACK }).params));
    const html = await assertPage(r, 200, /Allow access to Dynamics 365 Finance and Operations/);
    assert.ok(html.includes("&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt; &amp; &#39;Co&#39;"), "the client name is escaped");
    assert.ok(!html.includes("<script"), "no script element at all");
    assert.doesNotMatch(html, /<(img|link|iframe|object|embed)\b|\bsrc=/i, "nothing loads from elsewhere");
    assert.deepEqual(html.match(/\bhref="[^"]*"/g), ['href="/forget"'], "the only link stays on this server");
    assert.match(html, /<code>https:\/\/claude\.ai<\/code>/, "the page names where the result goes");
    assert.ok(!html.includes("auth_callback"), "the origin, not the full redirect URI");
    assert.match(html, /Read Dynamics 365 Finance and Operations data/);
    assert.doesNotMatch(html, /Create and change records/, "this server is read-only");
    assert.match(html, /<form method="post" action="\/consent">/);
    const form = consentForm(html);
    assert.equal(form.csrf.length, 43);
    const csrf = fresh.cookie("fo_csrf");
    assert.ok(csrf, "the form is bound to a cookie of this browser");
    assert.deepEqual([csrf.path, csrf.attributes.httponly, csrf.attributes.samesite, csrf.attributes.secure], ["/", true, "Lax", undefined]);
    assert.equal([...fresh.jar.keys()].some((n) => n.startsWith("fo_signin_") || n === "fo_consent"), false, "nothing is approved or bound yet");
  });

  it("posts the consent form to /consent also when the page was opened at /authorize/ with a trailing slash", async () => {
    const fresh = makeBrowser();
    const pageUrl = `${base}/authorize/?${new URLSearchParams(authorizeParams({ client_id: otherClient }).params)}`;
    const html = await assertPage(await fresh.fetch(pageUrl), 200);
    // A browser resolves the form action against the URL of the page, with the trailing slash in it.
    const action = new URL(/<form method="post" action="([^"]*)">/.exec(html)[1], pageUrl);
    assert.equal(action.href, `${base}/consent`);
    const approved = await fresh.fetch(action, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded", origin: base }, body: new URLSearchParams({ ...consentForm(html), action: "approve" }) });
    entraOf(approved);
  });

  it("asks Entra for its account picker when the approval was remembered, and lets Entra sign in silently right after a click on Approve", async () => {
    const fresh = makeBrowser();
    const approved = entraOf(await authorizeInBrowser(fresh, authorizeUrl(authorizeParams({ client_id: otherClient }).params)));
    assert.equal(approved.searchParams.get("prompt"), null, "the user just saw the consent page");
    // The server shows no page for a remembered client, so Entra shows one: a sign in the user did not start is visible there.
    const remembered = entraOf(await fresh.fetch(authorizeUrl(authorizeParams({ client_id: otherClient }).params)));
    assert.equal(remembered.searchParams.get("prompt"), "select_account");
    const back = await clientRedirectOf(await fresh.fetch(cloud.authorize(remembered.searchParams, "alice")));
    assert.ok(back.searchParams.get("code"), "the sign in finishes as before once the user picked the account");
  });

  it("forgets every remembered approval of a browser at /forget, which the consent page links to, and leaves the other cookies alone", async () => {
    const fresh = makeBrowser();
    entraOf(await authorizeInBrowser(fresh, authorizeUrl(authorizeParams({ client_id: otherClient }).params)));
    assert.ok(fresh.cookie("fo_consent"), "the approval is remembered");
    const forgotten = await fresh.fetch(`${base}/forget`);
    await assertPage(forgotten, 200, /This browser no longer remembers any approval/);
    assert.match(forgotten.headers.getSetCookie().join("\n"), /^fo_consent=;.*Path=\/;/m, "the consent cookie is cleared");
    assert.equal(fresh.cookie("fo_consent"), undefined);
    assert.ok(fresh.cookie("fo_csrf") && [...fresh.jar.keys()].some((n) => n.startsWith("fo_signin_")), "a sign in on its way to Entra is not touched");
    const html = await assertPage(await fresh.fetch(authorizeUrl(authorizeParams({ client_id: otherClient }).params)), 200, /Forget the approvals of this browser/);
    consentForm(html);
    assert.equal(new URL(/href="([^"]*)"/.exec(html)[1], base).href, `${base}/forget`, "the link on the consent page leads here");
  });

  it("remembers an approval in a signed cookie, binds the sign in to the browser and skips the page for that client afterwards", async () => {
    const fresh = makeBrowser();
    const first = await fresh.fetch(authorizeUrl(authorizeParams({ client_id: otherClient }).params));
    const approved = await postConsent(fresh, base, consentForm(await assertPage(first, 200)));
    assert.equal(approved.status, 303, "a redirect the browser follows with GET");
    entraOf(approved);
    assert.equal(approved.headers.get("cache-control"), "no-store");
    const consent = fresh.cookie("fo_consent");
    assert.deepEqual([consent.path, consent.attributes.httponly, consent.attributes.samesite, consent.attributes["max-age"]], ["/", true, "Lax", "2592000"]);
    assert.equal(consent.attributes.secure, undefined, "Secure only on an https origin");
    const binding = [...fresh.jar].find(([n]) => n.startsWith("fo_signin_"))?.[1];
    assert.ok(binding, "the sign in is bound to this browser");
    assert.deepEqual([binding.path, binding.attributes.httponly, binding.attributes.samesite, binding.attributes["max-age"]], ["/", true, "Lax", "600"]);

    entraOf(await fresh.fetch(authorizeUrl(authorizeParams({ client_id: otherClient }).params)));
    // Another client and another browser are asked again.
    consentForm(await assertPage(await fresh.fetch(authorizeUrl(authorizeParams({ client_id: testClient }).params)), 200));
    consentForm(await assertPage(await makeBrowser().fetch(authorizeUrl(authorizeParams({ client_id: otherClient }).params)), 200));

    // A consent cookie that was changed, or signed by someone else, counts for nothing.
    const [payload, mac] = consent.value.split(".");
    const tampered = makeBrowser();
    tampered.jar.set("fo_consent", { ...consent, value: `${payload}x.${mac}` });
    consentForm(await assertPage(await tampered.fetch(authorizeUrl(authorizeParams({ client_id: otherClient }).params)), 200));
  });

  it("asks again for a remembered approval once the server offers writes, needs another write role or reads another F&O environment", async () => {
    // One key for every server here, so a client and an approval of one are valid at the others and only the settings differ.
    const key = { MCP_STATE_KEY: "s".repeat(32) };
    const fresh = makeBrowser();
    let client;
    /** 200 when the browser gets the consent page for the client, 302 when it goes straight on to Entra. */
    const askedAt = async (at) => {
      const r = await fresh.fetch(authorizeUrl(authorizeParams({ client_id: client }).params, at));
      await r.text();
      return r.status;
    };
    await withServer(key, async (readOnly) => {
      client = await registerClient(readOnly.base);
      entraOf(await authorizeInBrowser(fresh, authorizeUrl(authorizeParams({ client_id: client }).params, readOnly.base)));
      assert.equal(await askedAt(readOnly.base), 302, "remembered on the server that showed the page");
    });
    await withServer(key, async (restarted) => assert.equal(await askedAt(restarted.base), 302, "and after a restart with the same settings"));
    // The approval was for a page that said Read only. Each of these shows another page, or reads other data.
    const writes = { FO_ALLOW_WRITES: "1", FO_WRITE_ENTITIES: "CustomerGroups" };
    const changed = [writes, { ...writes, MCP_WRITE_ROLE: "FO.Write" }, { FO_URL: cloud.foUrl.replace("localhost", "127.0.0.1") }];
    for (const env of changed) {
      await withServer({ ...key, ...env }, async (other) => assert.equal(await askedAt(other.base), 200, JSON.stringify(env)));
    }
    await withServer({ ...key, ...writes }, async (writing) => {
      const page = await fresh.fetch(authorizeUrl(authorizeParams({ client_id: client }).params, writing.base));
      assert.match(await assertPage(page, 200), /Create and change records/, "the user sees what is offered now");
    });
  });

  it("remembers the 20 most recent clients in one browser", async () => {
    const fresh = makeBrowser();
    const clients = [];
    for (let i = 0; i < 21; i++) {
      const client = await registerClient(base, { name: `client ${i}` });
      clients.push(client);
      entraOf(await authorizeInBrowser(fresh, authorizeUrl(authorizeParams({ client_id: client }).params)));
    }
    // The oldest approval made room for the newest.
    consentForm(await assertPage(await fresh.fetch(authorizeUrl(authorizeParams({ client_id: clients[0] }).params)), 200));
    for (const client of [clients[1], clients[20]]) entraOf(await fresh.fetch(authorizeUrl(authorizeParams({ client_id: client }).params)));
  });

  it("sends the client access_denied with its state and iss on Cancel and remembers nothing", async () => {
    const fresh = makeBrowser();
    const { params } = authorizeParams({ client_id: otherClient });
    const form = consentForm(await assertPage(await fresh.fetch(authorizeUrl(params)), 200));
    const cancelled = await postConsent(fresh, base, form, "cancel");
    assert.equal(cancelled.status, 303);
    const back = await errorRedirect(cancelled);
    assert.equal(back.searchParams.get("error"), "access_denied");
    assert.equal(back.searchParams.get("state"), params.state);
    assert.equal(fresh.cookie("fo_consent"), undefined, "nothing is remembered");
    assert.equal([...fresh.jar.keys()].some((n) => n.startsWith("fo_signin_")), false, "and nothing is bound for Entra");
    assert.equal(cloud.seen.authorizeRequests.length, 0);
  });

  it("refuses a consent POST from another browser, with a wrong CSRF token or an unknown action, and the right one still works", async () => {
    const owner = makeBrowser();
    const form = consentForm(await assertPage(await owner.fetch(authorizeUrl(authorizeParams({ client_id: otherClient }).params)), 200));
    const second = consentForm(await assertPage(await owner.fetch(authorizeUrl(authorizeParams({ client_id: otherClient }).params)), 200));
    const flipped = `${form.csrf.slice(0, -1)}${form.csrf.endsWith("A") ? "B" : "A"}`;
    await assertPage(await postConsent(makeBrowser(), base, form), 400, /another browser/);
    await assertPage(await postConsent(owner, base, { ...form, csrf: flipped }), 400);
    await assertPage(await postConsent(owner, base, { ...form, csrf: second.csrf }), 400); // the token of another sign in
    await assertPage(await postConsent(owner, base, { request: form.request }), 400);
    await assertPage(await postConsent(owner, base, form, "allow"), 400);
    const plain = await fetch(`${base}/consent`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded", origin: base }, body: new URLSearchParams({ ...form, action: "approve" }) });
    await assertPage(plain, 400);
    entraOf(await postConsent(owner, base, form));
    entraOf(await postConsent(owner, base, form)); // a second click on Approve goes to Entra again
  });

  it("refuses a consent POST that does not come from the server's own page, from another host of the same site too", async () => {
    // What a page on another *.azurecontainerapps.io app can send: its Lax cookies go along, so only the origin tells.
    const refused = [
      { origin: "https://evil.other-env.swedencentral.azurecontainerapps.io", "sec-fetch-site": "same-site" },
      { origin: "null", "sec-fetch-site": "same-site" },
      { origin: "null" },
      { "sec-fetch-site": "same-site" },
      { "sec-fetch-site": "cross-site" },
      {},
      { origin: `${base}.evil.example`, "sec-fetch-site": "same-origin" },
      { origin: base.replace("http:", "https:") },
    ];
    for (const headers of refused) {
      const victim = makeBrowser();
      const form = consentForm(await assertPage(await victim.fetch(authorizeUrl(authorizeParams({ client_id: otherClient }).params)), 200));
      const r = await victim.fetch(`${base}/consent`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded", ...headers }, body: new URLSearchParams({ ...form, action: "approve" }) });
      await assertPage(r, 403, /did not come from the approval page of this server/);
      assert.deepEqual(r.headers.getSetCookie(), [], `nothing is approved or bound for ${JSON.stringify(headers)}`);
    }
    assert.equal(cloud.seen.authorizeRequests.length, 0);

    // A browser sends the page's own origin, or at least Sec-Fetch-Site: same-origin.
    for (const headers of [{ origin: base }, { "sec-fetch-site": "same-origin" }, { origin: "null", "sec-fetch-site": "same-origin" }]) {
      const owner = makeBrowser();
      const form = consentForm(await assertPage(await owner.fetch(authorizeUrl(authorizeParams({ client_id: otherClient }).params)), 200));
      entraOf(await owner.fetch(`${base}/consent`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded", ...headers }, body: new URLSearchParams({ ...form, action: "approve" }) }));
    }
  });

  it("ignores a cookie whose name comes twice, so a CSRF or consent cookie planted next to the browser's own does not count", async () => {
    // The attacker's own consent page gives a form and the CSRF cookie it is bound to.
    const attacker = makeBrowser();
    const attackerForm = consentForm(await assertPage(await attacker.fetch(authorizeUrl(authorizeParams({ client_id: otherClient }).params)), 200));
    const planted = attacker.cookie("fo_csrf").value;
    const victim = makeBrowser();
    const victimForm = consentForm(await assertPage(await victim.fetch(authorizeUrl(authorizeParams({ client_id: otherClient }).params)), 200));
    const own = victim.cookie("fo_csrf").value;
    const post = (form, cookie) =>
      victim.fetch(`${base}/consent`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded", origin: base, cookie }, body: new URLSearchParams({ ...form, action: "approve" }) });
    // Which of the two the browser sends last depends on their paths and ages, so neither order may pass.
    await assertPage(await post(attackerForm, `fo_csrf=${own}; fo_csrf=${planted}`), 400);
    await assertPage(await post(attackerForm, `fo_csrf=${planted}; fo_csrf=${own}`), 400);
    await assertPage(await post(victimForm, `fo_csrf=${planted}; fo_csrf=${own}`), 400);
    entraOf(await post(victimForm, `fo_csrf=${own}`));

    // A remembered approval counts only when the browser sends one consent cookie.
    const consent = victim.cookie("fo_consent").value;
    const authorizeWith = (cookie) => victim.fetch(authorizeUrl(authorizeParams({ client_id: otherClient }).params), { headers: { cookie } });
    entraOf(await authorizeWith(`fo_consent=${consent}`));
    consentForm(await assertPage(await authorizeWith(`fo_consent=${consent}; fo_consent=${consent}`), 200));
  });

  // ------------------------------------------------------------ /callback

  it("answers /callback with 400 for an unknown, missing or already used state and never asks Entra", async () => {
    for (const query of ["state=no-such-sign-in&code=abc", "code=abc", "", "state=&code=abc"]) await assertPage(await browser.fetch(`${base}/callback?${query}`), 400);
    assert.deepEqual(cloud.seen.tokenGrants, [], "no code exchange for an unknown sign in");

    // A callback URL works once: a replay of the same Entra answer is an unknown sign in.
    const toCallback = cloud.authorize(entraOf(await authorize(authorizeParams().params)).searchParams, "alice");
    assert.equal((await browser.fetch(toCallback)).status, 302);
    await assertPage(await browser.fetch(toCallback), 400, /Unknown or expired/);
    assert.deepEqual(cloud.seen.tokenGrants, ["authorization_code"], "Entra was asked once");
  });

  it("refuses a state Entra already answered even with the binding cookie put back, and keeps a consent request and an Entra state apart", async () => {
    const owner = makeBrowser();
    const { params } = authorizeParams({ client_id: otherClient });
    const form = consentForm(await assertPage(await owner.fetch(authorizeUrl(params)), 200));
    const toEntra = entraOf(await postConsent(owner, base, form));
    const [name, binding] = [...owner.jar].find(([n]) => n.startsWith("fo_signin_"));
    const toCallback = cloud.authorize(toEntra.searchParams, "alice");
    assert.ok((await clientRedirectOf(await owner.fetch(toCallback))).searchParams.get("code"));
    // Nothing is stored for a sign in in progress, so the server remembers the states Entra answered to refuse them again.
    owner.jar.set(name, binding);
    await assertPage(await owner.fetch(toCallback), 400, /Unknown or expired/);
    assert.deepEqual(cloud.seen.tokenGrants, ["authorization_code"], "the replayed code never reaches Entra");

    // The consent request and the Entra state are sealed for their purpose, neither passes as the other.
    await assertPage(await owner.fetch(`${base}/callback?${new URLSearchParams({ state: form.request, code: "x" })}`), 400, /Unknown or expired/);
    await assertPage(await postConsent(owner, base, { ...form, request: toEntra.searchParams.get("state") }), 400, /expired/);
    // One changed character breaks the seal.
    const state = toEntra.searchParams.get("state");
    const altered = `${state.slice(0, 40)}${state[40] === "A" ? "B" : "A"}${state.slice(41)}`;
    await assertPage(await owner.fetch(`${base}/callback?${new URLSearchParams({ state: altered, code: "x" })}`), 400, /Unknown or expired/);
    assert.deepEqual(cloud.seen.tokenGrants, ["authorization_code"]);
  });

  it("refuses a state Entra already answered also in another spelling of the same sealed bytes", async () => {
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    const spellings = new Set();
    // The client's state goes into the sealed one, so three lengths of it cover every length of the sealed state modulo 4.
    for (const extra of ["", "x", "xx"]) {
      const owner = makeBrowser();
      const { params } = authorizeParams({ client_id: otherClient, state: `${random()}${extra}` });
      const toEntra = entraOf(await authorizeInBrowser(owner, authorizeUrl(params)));
      const [name, binding] = [...owner.jar].find(([n]) => n.startsWith("fo_signin_"));
      assert.ok((await clientRedirectOf(await owner.fetch(cloud.authorize(toEntra.searchParams, "alice")))).searchParams.get("code"));
      // Base64url decoding ignores one character too many and the unused low bits of the last character.
      const state = toEntra.searchParams.get("state");
      const variant = state.length % 4 === 0 ? `${state}A` : `${state.slice(0, -1)}${alphabet[alphabet.indexOf(state.at(-1)) ^ 1]}`;
      assert.ok(Buffer.from(variant, "base64url").equals(Buffer.from(state, "base64url")), "the variant stands for the same bytes");
      spellings.add(state.length % 4 === 0 ? "one character more" : "other low bits");
      const replay = new URL(cloud.authorize(toEntra.searchParams, "alice")); // a fresh Entra code for the same state
      replay.searchParams.set("state", variant);
      owner.jar.set(name, binding);
      const grants = cloud.seen.tokenGrants.length;
      await assertPage(await owner.fetch(replay.toString()), 400, /Unknown or expired/);
      assert.equal(cloud.seen.tokenGrants.length, grants, "the replayed code never reaches Entra");
    }
    assert.deepEqual([...spellings].sort(), ["one character more", "other low bits"]);
  });

  it("finishes a sign in on a restarted server with the same key, since nothing of it is kept in memory", async () => {
    const owner = makeBrowser();
    const { params, verifier } = authorizeParams({ client_id: otherClient });
    const form = consentForm(await assertPage(await owner.fetch(authorizeUrl(params)), 200));
    await withServer({}, async (restarted) => {
      // The consent page came from the first server, the approval and the callback go to the second.
      const toEntra = entraOf(await postConsent(owner, restarted.base, form));
      const done = await owner.fetch(cloud.authorize(toEntra.searchParams, "alice"));
      assert.equal(done.status, 302);
      const back = new URL(done.headers.get("location"));
      assert.equal(back.searchParams.get("state"), params.state);
      const tokens = await fetch(`${restarted.base}/token`, {
        method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ grant_type: "authorization_code", code: back.searchParams.get("code"), client_id: otherClient, redirect_uri: clientRedirect, code_verifier: verifier }),
      });
      assert.equal(tokens.status, 200);
    });
  });

  it("refuses /callback in a browser without the sign in's cookie, lets the right browser finish and clears the cookie", async () => {
    const owner = makeBrowser();
    const { params } = authorizeParams({ client_id: otherClient });
    const toCallback = cloud.authorize(entraOf(await authorizeInBrowser(owner, authorizeUrl(params))).searchParams, "alice");
    const [name, binding] = [...owner.jar].find(([n]) => n.startsWith("fo_signin_"));
    const wrong = makeBrowser();
    wrong.jar.set(name, { ...binding, value: random() + random() });
    for (const other of [makeBrowser(), wrong]) await assertPage(await other.fetch(toCallback), 400, /started in another browser/);
    await assertPage(await fetch(toCallback, { redirect: "manual" }), 400, /started in another browser/);
    assert.deepEqual(cloud.seen.tokenGrants, [], "no code exchange in a browser that did not start the sign in");

    const done = await owner.fetch(toCallback);
    const back = await clientRedirectOf(done);
    assert.ok(back.searchParams.get("code"));
    assert.equal(back.searchParams.get("state"), params.state);
    assert.equal(owner.cookie(name), undefined, "the binding cookie is cleared");
    assert.match(done.headers.getSetCookie().join("\n"), new RegExp(`^${name}=;.*Path=/;`, "m"));
  });

  it("passes an Entra error at /callback back to the client with the client's state, without Entra's trace lines", async () => {
    const { params } = authorizeParams();
    const entraState = entraOf(await authorize(params)).searchParams.get("state");
    const description = `AADSTS50126: Error validating credentials due to invalid username or password.\r\nTrace ID: ${ENTRA_TRACE}\r\nCorrelation ID: ${ENTRA_TRACE}\r\nTimestamp: 2026-10-09 10:00:00Z`;
    const r = await browser.fetch(`${base}/callback?${new URLSearchParams({ state: entraState, error: "access_denied", error_description: description })}`);
    const back = await errorRedirect(r);
    assert.equal(back.searchParams.get("error"), "access_denied");
    assert.equal(back.searchParams.get("error_description"), "AADSTS50126: Error validating credentials due to invalid username or password.");
    assert.equal(back.searchParams.get("state"), params.state);
    assert.deepEqual(cloud.seen.tokenGrants, [], "nothing to exchange after an Entra error");
    assert.match(await logLine(server, "AADSTS50126"), new RegExp(`Trace ID: ${ENTRA_TRACE}`), "the full text goes to the server log");
    // The error cleared the binding cookie, so a code that arrives later for the same sign in is not exchanged.
    await assertPage(await browser.fetch(`${base}/callback?state=${encodeURIComponent(entraState)}&code=late`), 400, /it is over/);
    assert.deepEqual(cloud.seen.tokenGrants, []);
  });

  it("sends server_error with the state to the client when Entra refuses the code at /callback", async () => {
    const { params } = authorizeParams();
    const entraState = entraOf(await authorize(params)).searchParams.get("state");
    const back = await errorRedirect(await browser.fetch(`${base}/callback?state=${encodeURIComponent(entraState)}&code=forged-code`));
    assert.equal(back.searchParams.get("error"), "server_error");
    assert.match(back.searchParams.get("error_description"), /unknown code/);
    assert.equal(back.searchParams.get("state"), params.state);
    assert.deepEqual(cloud.seen.tokenGrants, ["authorization_code"]);
  });

  it("never follows a redirect from Entra, so the client secret and the user's code stay with the configured authority", async () => {
    const { params } = authorizeParams();
    const toCallback = cloud.authorize(entraOf(await authorize(params)).searchParams, "alice");
    cloud.faults.entraRedirects = ["token"];
    const back = await errorRedirect(await browser.fetch(toCallback));
    assert.equal(back.searchParams.get("error"), "server_error");
    assert.match(back.searchParams.get("error_description"), /Entra answered with a redirect, which is not followed/);
    assert.equal(back.searchParams.get("state"), params.state);
    assert.deepEqual(cloud.seen.redirected, [], "nothing was sent on to the host the redirect named");
    assert.match(await logLine(server, "authorization_code request with a redirect"), /redirect to localhost:\d+, which is not followed\. Check FO_AUTHORITY\./);

    // At start the metadata check refuses a redirect too, before anything listens.
    cloud.faults.entraRedirects = ["discovery"];
    await assert.rejects(startServer({ cloud, certFile: cert.certFile }),
      /fo-mcp: Entra answered the metadata request for tenant [-0-9a-f]+ with a redirect to localhost:\d+, which is not followed\. Check FO_AUTHORITY\./);
    assert.deepEqual(cloud.seen.redirected, []);
  });

  it("fails a sign in whose Entra token has no oid claim instead of issuing a code", async () => {
    const { params } = authorizeParams();
    const toCallback = cloud.authorize(entraOf(await authorize(params)).searchParams, "ghost");
    const back = await errorRedirect(await browser.fetch(toCallback));
    assert.equal(back.searchParams.get("error"), "server_error");
    assert.match(back.searchParams.get("error_description"), /no oid claim/);
    assert.equal(back.searchParams.get("state"), params.state);
  });

  // ------------------------------------------------------------ /token, authorization_code

  it("answers a code exchange with a Bearer token, expires_in, a refresh token and the scope", async () => {
    const s = await signIn();
    const r = await exchange(s);
    assert.equal(r.status, 200, await r.clone().text());
    assert.match(r.headers.get("content-type"), /application\/json/);
    const t = await r.json();
    assert.equal(t.token_type, "Bearer");
    assert.equal(typeof t.access_token, "string");
    assert.doesNotMatch(t.access_token, /^ey/, "an opaque token, never the Entra JWT");
    assert.ok(Number.isInteger(t.expires_in) && t.expires_in > 3590 && t.expires_in <= 3600, `expires_in follows the Entra token: ${t.expires_in}`);
    assert.equal(typeof t.refresh_token, "string");
    assert.notEqual(t.refresh_token, t.access_token);
    assert.equal(t.scope, SCOPE);
    assert.equal((await mcpPost(serverUrl, t.access_token, INITIALIZE)).status, 200, "the access token opens /mcp");
  });

  it("marks token responses as not cacheable, as RFC 6749 section 5.1 requires", async () => {
    const s = await signIn();
    const code = await exchange(s);
    assert.equal(code.status, 200);
    const refresh = await tokenForm({ grant_type: "refresh_token", refresh_token: (await code.json()).refresh_token, client_id: s.client });
    assert.equal(refresh.status, 200);
    const headers = { "code exchange": code.headers.get("cache-control"), refresh: refresh.headers.get("cache-control") };
    assert.deepEqual(Object.entries(headers).filter(([, v]) => !/no-store/.test(v ?? "")), [],
      `every response with tokens must carry Cache-Control: no-store, got ${JSON.stringify(headers)}`);
  });

  it("refuses a code exchange with a wrong code_verifier, client_id or redirect_uri with invalid_grant, and an unknown client with invalid_client", async () => {
    const cases = [
      { code_verifier: "not-the-verifier-not-the-verifier-not-the-verifier" },
      { code_verifier: "" },
      { client_id: otherClient },
      { redirect_uri: "http://localhost:8787/other" },
      { redirect_uri: CLAUDE_CALLBACK },
      { redirect_uri: "" },
    ];
    for (const overrides of cases) {
      const s = await signIn();
      await assertOAuthError(await exchange(s, overrides), "invalid_grant");
    }
    // Leaving a field out is the same as a wrong value.
    for (const missing of ["code_verifier", "redirect_uri"]) {
      const s = await signIn();
      const fields = { grant_type: "authorization_code", code: s.code, client_id: s.client, redirect_uri: s.redirectUri, code_verifier: s.verifier };
      delete fields[missing];
      await assertOAuthError(await tokenForm(fields), "invalid_grant");
    }
    // A client this server never registered is refused before the code is looked at, so the code still works for its client.
    const s = await signIn();
    for (const client_id of ["", "dyn-someone-else", undefined]) await assertOAuthError(await exchange(s, { client_id }), "invalid_client", 401);
    assert.equal((await exchange(s)).status, 200);
  });

  it("refuses a code that was already exchanged and an unknown code with invalid_grant", async () => {
    const s = await signIn();
    assert.equal((await exchange(s)).status, 200);
    await assertOAuthError(await exchange(s), "invalid_grant");
    await assertOAuthError(await exchange({ ...s, code: "never-issued" }), "invalid_grant");
  });

  it("revokes the tokens of a code's first exchange when the code comes back, as RFC 6749 section 4.1.2 asks", async () => {
    const s = await signIn();
    const first = await (await exchange(s)).json();
    assert.equal((await mcpPost(serverUrl, first.access_token, INITIALIZE)).status, 200);
    const body = await assertOAuthError(await exchange(s), "invalid_grant");
    assert.match(body.error_description, /already used/);
    await assertUnauthorized(await mcpPost(serverUrl, first.access_token, INITIALIZE));
    await assertOAuthError(await tokenForm({ grant_type: "refresh_token", refresh_token: first.refresh_token, client_id: s.client }), "invalid_grant");
    assert.deepEqual(cloud.seen.tokenGrants, ["authorization_code"], "the revoked refresh token never reaches Entra");
  });

  it("answers an unknown grant_type or a missing body with 400 and an OAuth error, never 500", async () => {
    for (const grant of ["password", "client_credentials", "implicit", "urn:ietf:params:oauth:grant-type:jwt-bearer"]) {
      await assertOAuthError(await tokenForm({ grant_type: grant, client_id: testClient }), "unsupported_grant_type");
    }
    await assertOAuthError(await fetch(`${base}/token`, { method: "POST" }), "unsupported_grant_type");
    await assertOAuthError(await fetch(`${base}/token`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: "" }), "unsupported_grant_type");
    await assertOAuthError(await tokenJson({}), "unsupported_grant_type");
    await assertOAuthError(await tokenJson({ grant_type: ["authorization_code"] }), "unsupported_grant_type");
  });

  it("answers a JSON body with a number or an object where a string belongs with an OAuth error, never 500", async () => {
    // A JSON body with the right strings works, so what fails below is the type of the field.
    const good = await signIn();
    const ok = await tokenJson({ grant_type: "authorization_code", code: good.code, client_id: good.client, redirect_uri: good.redirectUri, code_verifier: good.verifier });
    assert.equal(ok.status, 200);

    const s = await signIn();
    await assertOAuthError(await tokenJson({ grant_type: "authorization_code", code: s.code, client_id: s.client, redirect_uri: s.redirectUri, code_verifier: 12345 }), "invalid_grant");
    const t = await signIn();
    await assertOAuthError(await tokenJson({ grant_type: "authorization_code", code: { $ne: null }, client_id: t.client, redirect_uri: t.redirectUri, code_verifier: t.verifier }), "invalid_grant");
    const u = await signIn();
    await assertOAuthError(await tokenJson({ grant_type: "authorization_code", code: u.code, client_id: 7, redirect_uri: u.redirectUri, code_verifier: u.verifier }), "invalid_client", 401);
    await assertOAuthError(await tokenJson({ grant_type: "refresh_token", refresh_token: 1, client_id: testClient }), "invalid_grant");
    // Repeated form fields arrive as arrays and must be refused the same way.
    const v = await signIn();
    await assertOAuthError(await fetch(`${base}/token`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" },
      body: `grant_type=authorization_code&code=${encodeURIComponent(v.code)}&code=x&client_id=${v.client}&redirect_uri=${encodeURIComponent(v.redirectUri)}&code_verifier=${v.verifier}` }), "invalid_grant");
  });

  // ------------------------------------------------------------ /token, refresh_token

  it("refuses a refresh with the right refresh token but another client_id and leaves the sign in intact", async () => {
    const provider = makeProvider(cloud, "alice");
    const client = await connectWithSignIn(serverUrl, provider);
    await client.close();
    const tokens = provider._tokens;
    const other = (client_id) => tokenForm({ grant_type: "refresh_token", refresh_token: tokens.refresh_token, client_id });
    await assertOAuthError(await other(otherClient), "invalid_grant");
    await assertOAuthError(await other("dyn-someone-else"), "invalid_client", 401);
    assert.equal(cloud.seen.tokenGrants.includes("refresh_token"), false, "the refused refresh never reaches Entra");
    assert.equal((await mcpPost(serverUrl, tokens.access_token, INITIALIZE)).status, 200, "the owner's access token still works");
    const own = await refreshAt(port, provider);
    assert.equal(own.status, 200, "and the owner can still refresh");
    assert.notEqual((await own.json()).access_token, tokens.access_token);
  });

  it("refuses another client_id that joins a refresh still waiting for Entra", async () => {
    const provider = makeProvider(cloud, "alice");
    const client = await connectWithSignIn(serverUrl, provider);
    await client.close();
    cloud.faults.refreshDelayMs = 300;
    const owner = refreshAt(port, provider);
    await new Promise((r) => setTimeout(r, 50));
    await assertOAuthError(await tokenForm({ grant_type: "refresh_token", refresh_token: provider._tokens.refresh_token, client_id: otherClient }), "invalid_grant");
    const mine = await owner;
    assert.equal(mine.status, 200);
    const fresh = await mine.json();
    assert.equal((await mcpPost(serverUrl, fresh.access_token, INITIALIZE)).status, 200);
  });

  it("answers invalid_grant with the AADSTS message but not Entra's trace lines when Entra refuses a refresh, and ends that sign in", async () => {
    const provider = makeProvider(cloud, "alice");
    const client = await connectWithSignIn(serverUrl, provider);
    await client.close();
    const tokens = provider._tokens;
    assert.equal((await mcpPost(serverUrl, tokens.access_token, INITIALIZE)).status, 200, "the access token works before the refresh");
    cloud.faults.refreshRefusals = 1;
    const body = await assertOAuthError(await refreshAt(port, provider), "invalid_grant");
    assert.match(body.error_description, /invalid_grant: AADSTS70043: The refresh token has expired or is invalid$/);
    assert.doesNotMatch(body.error_description, /Trace ID|Correlation ID|Timestamp|0b2fe5a1/);
    assert.match(await logLine(server, "AADSTS70043"), new RegExp(`refresh_token request with 400 invalid_grant: AADSTS70043.*Trace ID: ${ENTRA_TRACE}`));
    await assertUnauthorized(await mcpPost(serverUrl, tokens.access_token, INITIALIZE));
    await assertOAuthError(await refreshAt(port, provider), "invalid_grant");
    assert.deepEqual(cloud.seen.tokenGrants.filter((g) => g === "refresh_token"), ["refresh_token"], "the dead refresh token is not sent to Entra again");
  });

  it("ends a sign in when Entra answers its refresh with a token for another user, and never continues it with that token", async () => {
    const provider = makeProvider(cloud, "alice");
    const client = await connectWithSignIn(serverUrl, provider);
    await client.close();
    const tokens = provider._tokens;
    cloud.faults.refreshAs = "bob";
    const body = await assertOAuthError(await refreshAt(port, provider), "invalid_grant");
    assert.equal(body.error_description, "Entra answered the refresh for another user. Sign in again.");
    await assertUnauthorized(await mcpPost(serverUrl, tokens.access_token, INITIALIZE));
    await assertOAuthError(await refreshAt(port, provider), "invalid_grant");
    assert.deepEqual(cloud.seen.tokenGrants.filter((g) => g === "refresh_token"), ["refresh_token"], "the sign in is over, its refresh token is not sent to Entra again");
    assert.deepEqual(cloud.seen.foRequests.filter((r) => r.user === "bob@example.com"), [], "nothing ran as the other user");
  });

  it("recognises a refresh token exchanged any number of refreshes ago, so a thief who refreshes twice cannot shake off the owner", async () => {
    const chain = async () => {
      const s = await signIn();
      const refresh = (t, client = s.client) => tokenForm({ grant_type: "refresh_token", refresh_token: t.refresh_token, client_id: client });
      const first = await (await exchange(s)).json();
      const second = await (await refresh(first)).json();
      const third = await (await refresh(second)).json();
      return { refresh, first, second, third };
    };
    const works = async (t) => (await mcpPost(serverUrl, t.access_token, INITIALIZE)).status === 200;
    const a = await chain();
    // The latest exchanged token still gives a parallel request the same pair within the grace.
    const parallel = await a.refresh(a.second);
    assert.equal(parallel.status, 200);
    assert.equal((await parallel.json()).access_token, a.third.access_token);
    // Another client learns nothing from an old token and ends nothing with it, and a made up token names no sign in.
    assert.match((await assertOAuthError(await a.refresh(a.first, otherClient), "invalid_grant")).error_description, /Unknown or expired refresh token/);
    // A refresh token is the family, a random part and the server's signature over both. Anything that is not a token
    // this server issued names no sign in: one cut short in a log, the current one mangled by a client, an old one
    // with another family, random part or signature. Each of these once would have ended the sign in.
    const [family, part, signature] = a.first.refresh_token.split(".");
    assert.equal([family, part, signature].every((x) => /^[\w-]{43}$/.test(x ?? "")), true, a.first.refresh_token);
    for (const forged of [
      `${family}.`, `${family}.${part}`, `${family}.x.${signature}`, `nope.${part}.${signature}`, `${family}.${part}.${signature[0] === "A" ? "B" : "A"}${signature.slice(1)}`,
      `${a.third.refresh_token} `, `${a.third.refresh_token}x`, `${family}.${part}.${signature}.extra`, `.${part}.${signature}`,
    ]) {
      assert.match((await assertOAuthError(await a.refresh({ refresh_token: forged }), "invalid_grant")).error_description, /Unknown or expired refresh token/, forged);
      assert.equal((await revoke({ token: forged })).status, 200);
    }
    assert.equal(await works(a.third), true, "the sign in goes on");
    // The token before the latest was exchanged two refreshes ago. It is kept nowhere, yet presenting it ends the sign
    // in: whoever refreshed twice with a stolen token is out as soon as the owner uses the one they hold.
    assert.match((await assertOAuthError(await a.refresh(a.first), "invalid_grant")).error_description, /already used, this sign in is revoked/);
    assert.equal(await works(a.third), false, "the pair of the last refresh ended with the sign in");
    await assertOAuthError(await a.refresh(a.third), "invalid_grant");
    assert.match((await assertOAuthError(await a.refresh(a.first), "invalid_grant")).error_description, /Unknown or expired refresh token/, "an ended sign in knows no tokens");
    // /revoke ends a sign in by a token that old as well.
    const b = await chain();
    assert.equal((await revoke({ token: b.first.refresh_token })).status, 200);
    assert.equal(await works(b.third), false, "revoked by its first refresh token");
  });

  it("keeps at most 20 sign ins per user, ends the one refreshed least recently and leaves other users' sign ins alone", async () => {
    const works = async (t) => (await mcpPost(serverUrl, t.access_token, INITIALIZE)).status === 200;
    const refreshes = async (t) => (await tokenForm({ grant_type: "refresh_token", refresh_token: t.refresh_token, client_id: testClient })).status === 200;
    const bobs = await (await exchange(await signIn({ user: "bob" }))).json();
    // After these alice holds exactly 20, whatever earlier tests left her with: the stalest go first.
    const pairs = [];
    for (let i = 0; i < 20; i++) pairs.push(await (await exchange(await signIn())).json());
    assert.equal(await works(pairs[0]), true);
    // A refresh makes the first sign in the most recent one, so the second is now the stalest.
    const refreshed = await (await tokenForm({ grant_type: "refresh_token", refresh_token: pairs[0].refresh_token, client_id: testClient })).json();
    const twentyFirst = await (await exchange(await signIn())).json();
    assert.equal(await works(pairs[1]), false, "the stalest sign in of the user ended");
    assert.equal(await refreshes(pairs[1]), false, "its refresh token with it");
    for (const [name, pair] of [["the refreshed first", refreshed], ["the third", pairs[2]], ["the twentieth", pairs[19]], ["the new", twentyFirst], ["bob's", bobs]]) {
      assert.equal(await works(pair), true, `${name} sign in still works`);
    }
    assert.equal(await refreshes(twentyFirst), true);
  });

  it("answers a refresh with the same token response shape and a new pair", async () => {
    const s = await signIn();
    const first = await (await exchange(s)).json();
    const r = await tokenForm({ grant_type: "refresh_token", refresh_token: first.refresh_token, client_id: s.client });
    assert.equal(r.status, 200);
    const t = await r.json();
    assert.equal(t.token_type, "Bearer");
    assert.ok(Number.isInteger(t.expires_in) && t.expires_in > 3590 && t.expires_in <= 3600);
    assert.equal(t.scope, SCOPE);
    assert.notEqual(t.access_token, first.access_token);
    assert.notEqual(t.refresh_token, first.refresh_token);
    assert.deepEqual(cloud.seen.tokenGrants, ["authorization_code", "refresh_token"], "the refresh went to Entra with the Entra refresh token");
  });

  // ------------------------------------------------------------ /revoke

  it("revokes a whole sign in by its access token, its refresh token or an exchanged refresh token, and always answers 200", async () => {
    const pair = async () => (await exchange(await signIn())).json();
    const works = async (t) => (await mcpPost(serverUrl, t.access_token, INITIALIZE)).status === 200;
    const refreshes = async (t) => (await tokenForm({ grant_type: "refresh_token", refresh_token: t.refresh_token, client_id: testClient })).status === 200;

    const byAccess = await pair();
    const r = await revoke({ token: byAccess.access_token, token_type_hint: "access_token", client_id: testClient });
    assert.equal(r.status, 200);
    assert.equal(r.headers.get("cache-control"), "no-store");
    assert.equal(await works(byAccess), false, "the access token is revoked");
    assert.equal(await refreshes(byAccess), false, "and its refresh token with it");

    const byRefresh = await pair();
    assert.equal((await revoke({ token: byRefresh.refresh_token })).status, 200, "client_id is optional");
    assert.equal(await works(byRefresh), false);

    // An exchanged refresh token still names its sign in, so revoking it ends the pair issued after it.
    const rotated = await pair();
    const next = await (await tokenForm({ grant_type: "refresh_token", refresh_token: rotated.refresh_token, client_id: testClient })).json();
    assert.equal((await revoke({ token: rotated.refresh_token, token_type_hint: "refresh_token" })).status, 200);
    assert.equal(await works(next), false);

    // Another client cannot revoke this client's tokens, and unknown or missing tokens change nothing.
    const kept = await pair();
    for (const fields of [{ token: kept.access_token, client_id: otherClient }, { token: "no-such-token" }, {}, { token: kept.access_token, client_id: "dyn-someone-else" }]) {
      assert.equal((await revoke(fields)).status, 200, JSON.stringify(fields));
    }
    assert.equal(await works(kept), true);
    assert.equal(await refreshes(kept), true);
  });

  // ------------------------------------------------------------ metadata

  it("publishes authorization server and protected resource metadata that agree with each other and with the server URL", async () => {
    const as = await (await fetch(`${base}/.well-known/oauth-authorization-server`)).json();
    assert.deepEqual(as, {
      issuer: base,
      authorization_endpoint: `${base}/authorize`,
      token_endpoint: `${base}/token`,
      registration_endpoint: `${base}/register`,
      revocation_endpoint: `${base}/revoke`,
      response_types_supported: ["code"],
      grant_types_supported: ["authorization_code", "refresh_token"],
      code_challenge_methods_supported: ["S256"],
      token_endpoint_auth_methods_supported: ["none"],
      revocation_endpoint_auth_methods_supported: ["none"],
      scopes_supported: [SCOPE],
      authorization_response_iss_parameter_supported: true,
    });
    for (const path of ["/.well-known/oauth-authorization-server/mcp", "/.well-known/openid-configuration"]) {
      assert.deepEqual(await (await fetch(`${base}${path}`)).json(), as, `${path} serves the same document`);
    }

    const prm = await (await fetch(`${base}/.well-known/oauth-protected-resource/mcp`)).json();
    assert.equal(prm.resource, serverUrl);
    assert.equal(serverUrl, `${base}/mcp`);
    assert.deepEqual(prm.authorization_servers, [as.issuer]);
    assert.deepEqual(prm.scopes_supported, as.scopes_supported);
    const root = await (await fetch(`${base}/.well-known/oauth-protected-resource`)).json();
    assert.equal(root.resource, prm.resource);
    assert.deepEqual(root.authorization_servers, prm.authorization_servers);
    assert.deepEqual(root.scopes_supported, prm.scopes_supported);

    // The WWW-Authenticate of /mcp points at that same document.
    const challenge = await assertUnauthorized(await fetch(serverUrl, { method: "POST", headers: { "content-type": "application/json" }, body: "{}" }));
    assert.match(challenge, /resource_metadata="http:\/\/localhost:\d+\/\.well-known\/oauth-protected-resource\/mcp"/);

    // And the endpoints it lists are the ones that answer.
    const reg = await fetch(as.registration_endpoint, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ redirect_uris: [clientRedirect] }) });
    assert.equal(reg.status, 201);
    assert.ok(as.token_endpoint_auth_methods_supported.includes((await reg.json()).token_endpoint_auth_method));
    const toEntra = entraOf(await authorize(authorizeParams().params));
    assert.equal(toEntra.searchParams.get("redirect_uri"), `${as.issuer}/callback`);
    await assertOAuthError(await fetch(as.token_endpoint, { method: "POST" }), "unsupported_grant_type");
    assert.equal((await fetch(as.revocation_endpoint, { method: "POST" })).status, 200);
  });

  it("builds every metadata URL, the Entra callback and Secure cookies from an https MCP_PUBLIC_URL behind a proxy", async () => {
    // A public server may not skip certificate checks towards F&O, so it trusts the fake cloud's certificate explicitly.
    await withServer({ MCP_PUBLIC_URL: "https://mcp.example.com/fo/mcp", MCP_ALLOWED_HOSTS: "localhost", FO_INSECURE_TLS: "0", FO_CA_FILE: cert.certFile }, async (proxied) => {
      const local = proxied.base;
      const as = await (await fetch(`${local}/.well-known/oauth-authorization-server`)).json();
      assert.equal(as.issuer, "https://mcp.example.com");
      assert.equal(as.authorization_endpoint, "https://mcp.example.com/authorize");
      assert.equal(as.token_endpoint, "https://mcp.example.com/token");
      assert.equal(as.registration_endpoint, "https://mcp.example.com/register");
      assert.equal(as.revocation_endpoint, "https://mcp.example.com/revoke");
      const prm = await (await fetch(`${local}/.well-known/oauth-protected-resource/fo/mcp`)).json();
      assert.equal(prm.resource, "https://mcp.example.com/fo/mcp");
      assert.deepEqual(prm.authorization_servers, ["https://mcp.example.com"]);
      assert.deepEqual(prm.scopes_supported, as.scopes_supported);
      const r = await fetch(`${local}/fo/mcp`, { method: "POST", headers: { "content-type": "application/json" }, body: "{}" });
      assert.equal(r.status, 401);
      assert.equal(/resource_metadata="([^"]+)"/.exec(r.headers.get("www-authenticate"))?.[1], "https://mcp.example.com/.well-known/oauth-protected-resource/fo/mcp");

      // The browser sees the public origin, so that is the origin it sends with the consent form.
      const fromPage = { origin: "https://mcp.example.com" };
      const proxiedBrowser = makeBrowser();
      const page = await proxiedBrowser.fetch(authorizeUrl(authorizeParams().params, local));
      const form = consentForm(await assertPage(page, 200));
      assert.equal(page.headers.get("strict-transport-security"), "max-age=31536000", "every answer of an https server asks the browser to stay on https");

      // Another *.azurecontainerapps.io app can set a cookie named fo_csrf for the parent domain, never one with the
      // __Host- prefix. The server reads only the prefixed one, so the attacker's form fails in the victim's browser.
      const attacker = makeBrowser();
      const attackerForm = consentForm(await assertPage(await attacker.fetch(authorizeUrl(authorizeParams().params, local)), 200));
      const tossed = `__Host-fo_csrf=${proxiedBrowser.cookie("__Host-fo_csrf").value}; fo_csrf=${attacker.cookie("__Host-fo_csrf").value}`;
      await assertPage(await proxiedBrowser.fetch(`${local}/consent`, {
        method: "POST", headers: { "content-type": "application/x-www-form-urlencoded", origin: fromPage.origin, cookie: tossed }, body: new URLSearchParams({ ...attackerForm, action: "approve" }),
      }), 400, /expired or was opened in another browser/);

      const toEntra = entraOf(await postConsent(proxiedBrowser, local, form, "approve", fromPage));
      assert.equal(toEntra.searchParams.get("redirect_uri"), "https://mcp.example.com/callback");
      const binding = [...proxiedBrowser.jar].find(([n]) => n.startsWith("__Host-fo_signin_"));
      assert.ok(binding, `the binding cookie has the __Host- prefix: ${[...proxiedBrowser.jar.keys()]}`);
      for (const [name, cookie] of [["__Host-fo_csrf", proxiedBrowser.cookie("__Host-fo_csrf")], ["__Host-fo_consent", proxiedBrowser.cookie("__Host-fo_consent")], binding]) {
        assert.ok(cookie, `${name} is set`);
        assert.deepEqual([cookie.path, cookie.attributes.secure, cookie.attributes.domain], ["/", true, undefined], `${name} has Path=/, Secure and no Domain, as the prefix requires`);
      }
      assert.equal([...proxiedBrowser.jar.keys()].some((n) => n.startsWith("fo_")), false, "no cookie without the prefix");
      // The prefixed binding cookie finishes the sign in at /callback.
      const done = await proxiedBrowser.fetch(cloud.authorize(toEntra.searchParams, "alice").replace("https://mcp.example.com", local));
      assert.equal(done.status, 302);
      const back = new URL(done.headers.get("location"));
      assert.equal(back.searchParams.get("iss"), "https://mcp.example.com");
      assert.ok(back.searchParams.get("code"), back.searchParams.get("error_description") ?? "");
      for (const path of ["/health", "/.well-known/oauth-authorization-server", "/fo/mcp"]) {
        assert.equal((await fetch(`${local}${path}`, { method: path === "/fo/mcp" ? "POST" : "GET" })).headers.get("strict-transport-security"), "max-age=31536000", path);
      }
      assert.match(proxied.server.log(), /listening on 0\.0\.0\.0:\d+/, "a public server listens on every interface");
    });
    for (const path of ["/health", "/authorize"]) assert.equal((await fetch(`${base}${path}`)).headers.get("strict-transport-security"), null, `no HSTS on plain http: ${path}`);
  });

  // ------------------------------------------------------------ tokens presented straight from Entra

  it("accepts an Entra user token for api://<client id> or the bare client id, the controls for the rejections below", async () => {
    for (const audience of [`api://${clientId}`, clientId]) {
      const r = await mcpPost(serverUrl, await cloud.userToken("alice", audience), INITIALIZE);
      assert.equal(r.status, 200, `audience ${audience}`);
    }
  });

  it("answers 401 with resource_metadata for an Entra-shaped token signed by a key the tenant does not publish", async () => {
    await assertUnauthorized(await mcpPost(serverUrl, await cloud.foreignToken(`api://${clientId}`), INITIALIZE));
  });

  it("answers 401 with resource_metadata for a token with a wrong issuer", async () => {
    await assertUnauthorized(await mcpPost(serverUrl, await cloud.foreignToken(`api://${clientId}`, { wrongIssuer: true }), INITIALIZE));
  });

  it("answers 401 with resource_metadata for a token whose audience is neither api://<client id> nor the client id", async () => {
    for (const audience of ["api://some-other-app", `api://${clientId}/`, cloud.foUrl, "00000003-0000-0000-c000-000000000000"]) {
      await assertUnauthorized(await mcpPost(serverUrl, await cloud.userToken("alice", audience), INITIALIZE));
    }
  });

  it("answers 401 for an unsigned token and for a user token without the access_as_user scope", async () => {
    const enc = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
    const now = Math.floor(Date.now() / 1000);
    const unsigned = `${enc({ alg: "none", typ: "JWT" })}.${enc({ iss: cloud.issuer, aud: `api://${clientId}`, scp: "access_as_user", preferred_username: "mallory@example.com", oid: "oid-mallory", tid: tenantId, azp: clientId, iat: now, exp: now + 3600 })}.`;
    await assertUnauthorized(await mcpPost(serverUrl, unsigned, INITIALIZE));
    await assertUnauthorized(await mcpPost(serverUrl, await cloud.userToken("alice", `api://${clientId}`, { scp: "User.Read" }), INITIALIZE));
  });

  it("refuses a direct token from another tenant, without a tenant or without an oid", async () => {
    const audience = `api://${clientId}`;
    for (const overrides of [{ tid: "00000000-0000-0000-0000-000000000000" }, { tid: undefined }, { oid: undefined }, { oid: "" }]) {
      const header = await assertUnauthorized(await mcpPost(serverUrl, await cloud.userToken("alice", audience, overrides), INITIALIZE));
      assert.match(header, "tid" in overrides ? /not from this tenant/ : /no oid claim/, JSON.stringify(overrides));
    }
    assert.equal((await mcpPost(serverUrl, await cloud.userToken("alice", audience, { tid: tenantId.toUpperCase() }), INITIALIZE)).status, 200, "a GUID in capitals is the same tenant");
  });

  it("accepts direct tokens only from the apps on MCP_ALLOWED_CLIENT_APPS, by azp or by appid in v1 tokens", async () => {
    const audience = `api://${clientId}`;
    const status = async (url, overrides) => (await mcpPost(url, await cloud.userToken("alice", audience, overrides), INITIALIZE)).status;
    // By default only the server's own app.
    assert.equal(await status(serverUrl, { azp: undefined, appid: clientId }), 200, "a v1 token names the app in appid");
    assert.equal(await status(serverUrl, { azp: OTHER_APP }), 401);
    assert.equal(await status(serverUrl, { azp: undefined }), 401, "a token that names no app is refused");
    const header = (await mcpPost(serverUrl, await cloud.userToken("alice", audience, { azp: OTHER_APP }), INITIALIZE)).headers.get("www-authenticate");
    assert.match(header, /MCP_ALLOWED_CLIENT_APPS/);

    await withServer({ MCP_ALLOWED_CLIENT_APPS: ` ${OTHER_APP.toUpperCase()} ` }, async (other) => {
      assert.equal(await status(other.url, { azp: OTHER_APP }), 200, "the listed app");
      assert.equal(await status(other.url, {}), 401, "the server's own app is no longer on the list");
    });
    await withServer({ MCP_ALLOWED_CLIENT_APPS: "none" }, async (closed) => {
      assert.equal(await status(closed.url, {}), 401, "no direct tokens at all");
      // Sign ins through the server's own OAuth front still work.
      const client = await connectWithSignIn(closed.url, makeProvider(cloud, "bob"));
      await client.close();
    });
  });

  it("accepts no direct tokens by default off localhost, not even of the server's own app, and says so when it starts", async () => {
    assert.match(server.log(), /direct Entra tokens of FO_CLIENT_ID, the default on localhost/);
    const audience = `api://${clientId}`;
    const publicServer = { MCP_PUBLIC_URL: "https://mcp.example.com/mcp", MCP_ALLOWED_HOSTS: "localhost", FO_INSECURE_TLS: "0", FO_CA_FILE: cert.certFile };
    await withServer(publicServer, async (hosted) => {
      assert.match(hosted.server.log(), /no direct Entra tokens, the default off localhost \(MCP_ALLOWED_CLIENT_APPS lists the apps to accept\)/);
      const r = await mcpPost(hosted.url, await cloud.userToken("alice", audience), INITIALIZE);
      assert.equal(r.status, 401);
      assert.match(r.headers.get("www-authenticate") ?? "", /Unknown token\. Sign in through your MCP client\./);
    });
    // Listed explicitly, the server's own app works there too.
    await withServer({ ...publicServer, MCP_ALLOWED_CLIENT_APPS: clientId }, async (hosted) => {
      assert.match(hosted.server.log(), new RegExp(`direct Entra tokens of ${clientId} \\(MCP_ALLOWED_CLIENT_APPS\\)`));
      assert.equal((await mcpPost(hosted.url, await cloud.userToken("alice", audience), INITIALIZE)).status, 200);
    });
  });

  it("keeps the WWW-Authenticate challenge well formed for every rejected token, so strict clients can read resource_metadata", async () => {
    const audience = `api://${clientId}`;
    const tokens = {
      "unknown key": await cloud.foreignToken(audience),
      "wrong issuer": await cloud.foreignToken(audience, { wrongIssuer: true }),
      "wrong audience": await cloud.userToken("alice", "api://some-other-app"),
      "opaque garbage": "not-a-token",
      "no scope": await cloud.userToken("alice", audience, { scp: "User.Read" }),
      "other tenant": await cloud.userToken("alice", audience, { tid: "00000000-0000-0000-0000-000000000000" }),
      "other app": await cloud.userToken("alice", audience, { azp: OTHER_APP }),
      "no oid": await cloud.userToken("alice", audience, { oid: undefined }),
    };
    const malformed = [];
    for (const [name, token] of Object.entries(tokens)) {
      const r = await mcpPost(serverUrl, token, INITIALIZE);
      assert.equal(r.status, 401, name);
      const header = r.headers.get("www-authenticate");
      const params = parseChallenge(header);
      if (!params) {
        malformed.push(`${name}: ${header}`);
        continue;
      }
      assert.equal(params.error, "invalid_token", name);
      assert.equal(params.resource_metadata, `${base}/.well-known/oauth-protected-resource/mcp`, name);
    }
    assert.deepEqual(malformed, [], "these challenges are not valid RFC 7235 Bearer challenges (an unescaped double quote inside error_description)");
  });
});
