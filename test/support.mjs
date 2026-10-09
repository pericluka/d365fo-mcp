// Shared test support: a fake Entra tenant and a fake F&O environment on one HTTPS port, helpers to start the
// remote server (dist/http.js) and the local stdio server (dist/index.js) against them, and the client side of
// the OAuth sign in with the browser replaced by fetches. Nothing real is contacted.
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { UnauthorizedError } from "@modelcontextprotocol/sdk/client/auth.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { exportJWK, generateKeyPair, jwtVerify, SignJWT } from "jose";
import assert from "node:assert/strict";
import { execFileSync, spawn, spawnSync } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { copyFileSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { createServer as createHttpsServer } from "node:https";
import { createServer as createTcpServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

export const projectDir = fileURLToPath(new URL("..", import.meta.url));

// ---------------------------------------------------------------- What this machine can run

/**
 * Why the tests that make certificates cannot run here, for the skip option of describe, or false when they can.
 * makeCert runs openssl, which macOS and Linux have. Windows has it in WSL, or with Git for Windows' usr\bin on the PATH.
 */
export const NO_OPENSSL = spawnSync("openssl", ["version"], { stdio: "ignore" }).error
  ? "openssl is not on the PATH, and the fake cloud needs it for its test certificate. Install it, or run the tests in WSL on Windows."
  : false;

/**
 * Why the tests of a graceful shutdown on SIGTERM cannot run on a platform, or false when they can. On Windows
 * child.kill("SIGTERM") ends the process at once, so its signal handler never runs.
 */
export function noSignals(platform = process.platform) {
  return platform === "win32" ? "Windows has no POSIX signals, kill() ends the process at once, so the server's SIGTERM handler cannot run." : false;
}

/**
 * Stop a process and the processes it started, such as the CLI of an eval run and the MCP server it runs. On macOS and
 * Linux child must have been spawned with detached, so it leads a process group of its own and the signal reaches the
 * whole group. Windows has no process groups, there taskkill /T ends child and what it started, which needs child to be
 * still running. When taskkill fails, child itself is still ended. Never throws, also for a process that has exited.
 */
export function stopProcessTree(child, signal = "SIGTERM", { platform = process.platform, run = spawnSync } = {}) {
  if (platform === "win32") {
    const result = run("taskkill", ["/pid", String(child.pid), "/T", "/F"], { stdio: "ignore", windowsHide: true });
    if (result.error || result.status !== 0) child.kill(signal);
    return;
  }
  try {
    process.kill(-child.pid, signal);
  } catch {
    // No such group: child was not detached, or it and everything it started have exited.
    child.kill(signal);
  }
}
export const tenantId = "11111111-2222-3333-4444-555555555555";
export const clientId = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
export const clientSecret = "test-secret";
export const clientRedirect = "http://localhost:8787/callback";

export const s256 = (value) => createHash("sha256").update(value).digest("base64url");
export const random = () => randomBytes(16).toString("base64url");
export const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/**
 * The timeout of every describe. In node:test a timeout on a suite caps the suite as a whole, not each test: when it
 * fires the suite fails and every test still to run is cancelled, and each test inherits the value as its own. npm test
 * runs the files at the same time, so the suites share the machine, the slowest takes about 30 seconds then, and a
 * laptop on battery or a shared CI runner is several times slower than this one. Five minutes keeps those green and
 * still ends a run that hangs.
 */
export const SUITE_TIMEOUT = 300_000;

/**
 * Listen on 127.0.0.1, on a port the OS picks unless one is given, and return the port. A failure at listen, a port in
 * use for example, rejects here instead of ending the test file as an error event nobody listens to.
 */
export function listenOn(server, port = 0) {
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, "127.0.0.1", () => {
      server.off("error", reject);
      resolve(server.address().port);
    });
  });
}

/**
 * A port nothing listens on at this moment, for a server under test that must know its port before it starts, MCP_PORT
 * in the public URL. Nothing reserves it: a test file running at the same time can be handed the same number a moment
 * later, which startServer allows for. The fakes of the tests listen on port 0 instead and read their port back.
 */
export async function freePort() {
  const server = createTcpServer();
  const port = await listenOn(server);
  await new Promise((resolve, reject) => server.close((err) => (err ? reject(err) : resolve())));
  return port;
}

/** A self-signed certificate for localhost in a temporary folder. Call remove() when done. */
export function makeCert() {
  if (NO_OPENSSL) throw new Error(NO_OPENSSL);
  const dir = mkdtempSync(join(tmpdir(), "fo-mcp-test-"));
  execFileSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2", "-subj", "/CN=localhost",
    "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1", "-keyout", join(dir, "key.pem"), "-out", join(dir, "cert.pem")], { stdio: "ignore" });
  return { dir, certFile: join(dir, "cert.pem"), remove: () => rmSync(dir, { recursive: true, force: true }) };
}

/**
 * A copy of the built server in dir, with a package.json of its own and the project's node_modules linked in. The
 * server loads .env from the folder of its package.json, so the copy sees whatever .env dir holds and never the
 * developer's. A junction needs no privilege on Windows, elsewhere the type is ignored. Returns dir.
 */
export function copyBuiltServer(dir) {
  const { name, version } = JSON.parse(readFileSync(join(projectDir, "package.json"), "utf8"));
  mkdirSync(join(dir, "dist"), { recursive: true });
  for (const file of readdirSync(join(projectDir, "dist")).filter((f) => f.endsWith(".js"))) copyFileSync(join(projectDir, "dist", file), join(dir, "dist", file));
  writeFileSync(join(dir, "package.json"), JSON.stringify({ name, version, type: "module" }));
  symlinkSync(join(projectDir, "node_modules"), join(dir, "node_modules"), "junction");
  return dir;
}

// ---------------------------------------------------------------- Fake F&O data

const entityRow = (name, publicName, collection, extra = {}) => ({
  Name: name, PublicEntityName: publicName, PublicCollectionName: collection, LabelId: `@TST_${publicName}`,
  DataServiceEnabled: true, DataManagementEnabled: true, EntityCategory: "Master", IsReadOnly: false, ...extra,
});

const field = (name, dataType = "String", extra = {}) => ({
  Name: name, TypeName: extra.TypeName ?? "", DataType: dataType, LabelId: extra.LabelId ?? `@TST_${name}`,
  IsKey: !!extra.IsKey, IsMandatory: !!(extra.IsMandatory ?? extra.IsKey), AllowEdit: extra.AllowEdit ?? !extra.IsKey, AllowEditOnCreate: true,
});

/** The entities of the fake environment: what /Metadata/DataEntities lists. */
export const DATA_ENTITIES = [
  entityRow("CustCustomerV3Entity", "CustomerV3", "CustomersV3"),
  entityRow("SalesOrderHeaderV2Entity", "SalesOrderHeaderV2", "SalesOrderHeadersV2"),
  entityRow("SalesOrderLineEntity", "SalesOrderLine", "SalesOrderLines"),
  entityRow("CustCustomerGroupEntity", "CustomerGroup", "CustomerGroups"),
  entityRow("LegalEntityEntity", "LegalEntity", "LegalEntities"),
  entityRow("CurrencyEntity", "Currency", "Currencies"),
  entityRow("BigRowEntity", "BigRow", "BigRows"),
  entityRow("HiddenThingEntity", "HiddenThing", "HiddenThings", { DataServiceEnabled: false }),
];

/** What /Metadata/PublicEntities answers per EntitySetName. */
export const PUBLIC_ENTITIES = {
  CustomersV3: {
    Name: "CustomerV3", EntitySetName: "CustomersV3", LabelId: "@TST_CustomerV3", IsReadOnly: false,
    NavigationProperties: [{ Name: "CustomerGroup", RelatedEntity: "CustomerGroup", RelatedRelationName: "Customers", Cardinality: "ZeroOne" }],
    Properties: [field("dataAreaId", "String", { IsKey: true }), field("CustomerAccount", "String", { IsKey: true }), field("OrganizationName"),
      field("CustomerGroupId"), field("CreditLimit", "Real"), field("Blocked", "Enum", { TypeName: "CustVendorBlocked" })],
  },
  SalesOrderHeadersV2: {
    Name: "SalesOrderHeaderV2", EntitySetName: "SalesOrderHeadersV2", LabelId: "@TST_SalesOrderHeaderV2", IsReadOnly: false,
    NavigationProperties: [{ Name: "SalesOrderLines", RelatedEntity: "SalesOrderLine", RelatedRelationName: "SalesOrderHeader", Cardinality: "Multiple" }],
    Properties: [field("dataAreaId", "String", { IsKey: true }), field("SalesOrderNumber", "String", { IsKey: true }),
      field("SalesOrderStatus", "Enum", { TypeName: "SalesStatus" }), field("RequestedShippingDate", "Date"), field("OrderingCustomerAccountNumber")],
  },
  SalesOrderLines: {
    Name: "SalesOrderLine", EntitySetName: "SalesOrderLines", LabelId: "@TST_SalesOrderLine", IsReadOnly: false,
    NavigationProperties: [{ Name: "SalesOrderHeader", RelatedEntity: "SalesOrderHeaderV2", RelatedRelationName: "SalesOrderLines", Cardinality: "ZeroOne" }],
    Properties: [field("dataAreaId", "String", { IsKey: true }), field("InventoryLotId", "String", { IsKey: true }), field("SalesOrderNumber"), field("ItemNumber")],
  },
  CustomerGroups: {
    Name: "CustomerGroup", EntitySetName: "CustomerGroups", LabelId: "@TST_CustomerGroup", IsReadOnly: false,
    NavigationProperties: [],
    Properties: [field("dataAreaId", "String", { IsKey: true }), field("CustomerGroupId", "String", { IsKey: true }), field("Description"),
      field("PaymentTermId"), field("ClearingPeriodPaymentTermName", "String", { AllowEdit: false })],
  },
  LegalEntities: {
    Name: "LegalEntity", EntitySetName: "LegalEntities", LabelId: "@TST_LegalEntity", IsReadOnly: true, NavigationProperties: [],
    Properties: [field("LegalEntityId", "String", { IsKey: true }), field("Name")],
  },
  Currencies: {
    Name: "Currency", EntitySetName: "Currencies", LabelId: "@TST_Currency", IsReadOnly: false, NavigationProperties: [],
    Properties: [field("CurrencyCode", "String", { IsKey: true }), field("Name")],
  },
  BigRows: {
    Name: "BigRow", EntitySetName: "BigRows", LabelId: "@TST_BigRow", IsReadOnly: true, NavigationProperties: [],
    Properties: [field("Id", "String", { IsKey: true }), field("Payload")],
  },
};

/** The element names of the enums the fake's entities use, what /Metadata/PublicEnumerations answers. */
export const ENUMS = {
  CustVendorBlocked: ["No", "Invoice", "All", "Payment", "Requisition", "Never"],
  SalesStatus: ["None", "Backorder", "Delivered", "Invoiced", "Canceled"],
  NoYes: ["No", "Yes"],
};

/** Terms of payment the fake accepts in CustomerGroups.PaymentTermId. Anything else fails like F&O does, with the infolog nested inside. */
export const PAYMENT_TERMS = ["Net10", "Net15", "Net30", "Net60"];

/** The nested error shape of a write that X++ refused: the infolog sits in innererror, next to stack traces that must never reach the model. */
export function writeFailed(table, infolog) {
  return {
    error: {
      code: "",
      message: "An error has occurred.",
      innererror: {
        message: `Write failed for table row of type '${table}'. Infolog: Error: ${infolog}`,
        type: "Microsoft.Dynamics.Platform.Integration.Services.OData.AxODataWriteException",
        stacktrace: "   at Microsoft.Dynamics.Platform.Integration.Services.OData.AxODataWriteException.Throw()",
        internalexception: {
          message: "Exception of type 'Microsoft.Dynamics.Ax.Xpp.ErrorException' was thrown.",
          type: "Microsoft.Dynamics.Ax.Xpp.ErrorException",
          stacktrace: "   at Dynamics.AX.Application.CustGroup.validateWrite()",
        },
      },
    },
  };
}

/** Fresh copies of the rows of every collection, so tests that write do not leak into others. */
function seedTables() {
  return {
    CustomersV3: [
      { dataAreaId: "usmf", CustomerAccount: "US-001", OrganizationName: "Contoso Retail San Diego", CustomerGroupId: "10", CreditLimit: 1000, Blocked: "No" },
      { dataAreaId: "usmf", CustomerAccount: "US-002", OrganizationName: "Contoso Retail Los Angeles", CustomerGroupId: "10", CreditLimit: 2000, Blocked: "No" },
      { dataAreaId: "usmf", CustomerAccount: "US-003", OrganizationName: "O'Brien Supplies", CustomerGroupId: "20", CreditLimit: 0, Blocked: "All" },
      { dataAreaId: "demf", CustomerAccount: "DE-001", OrganizationName: "Contoso Europe", CustomerGroupId: "10", CreditLimit: 500, Blocked: "No" },
    ],
    SalesOrderHeadersV2: [
      { dataAreaId: "usmf", SalesOrderNumber: "SO-1", SalesOrderStatus: "Backorder", RequestedShippingDate: "2016-01-20T12:00:00Z", OrderingCustomerAccountNumber: "US-001" },
      { dataAreaId: "usmf", SalesOrderNumber: "SO-2", SalesOrderStatus: "Invoiced", RequestedShippingDate: "2016-01-10T12:00:00Z", OrderingCustomerAccountNumber: "US-002" },
    ],
    SalesOrderLines: [
      { dataAreaId: "usmf", InventoryLotId: "L-1", SalesOrderNumber: "SO-1", ItemNumber: "A0001" },
      { dataAreaId: "usmf", InventoryLotId: "L-2", SalesOrderNumber: "SO-1", ItemNumber: "A0002" },
    ],
    CustomerGroups: [
      { dataAreaId: "usmf", CustomerGroupId: "10", Description: "Wholesale", PaymentTermId: "Net30", ClearingPeriodPaymentTermName: "" },
      { dataAreaId: "usmf", CustomerGroupId: "20", Description: "Retail", PaymentTermId: "Net10", ClearingPeriodPaymentTermName: "" },
    ],
    LegalEntities: [{ LegalEntityId: "DEMF", Name: "Contoso Entertainment System Germany" }, { LegalEntityId: "USMF", Name: "Contoso Entertainment System USA" }],
    Currencies: [{ CurrencyCode: "EUR", Name: "Euro" }, { CurrencyCode: "USD", Name: "US Dollar" }],
  };
}

// ---------------------------------------------------------------- Fake cloud

/** The Trace ID and Correlation ID the fake Entra puts at the end of an error description. */
export const ENTRA_TRACE = "0b2fe5a1-7c3d-4e8f-9a6b-1c2d3e4f5a6b";

/** What fo() returns for a request whose connection the fake closes without an answer. */
const DROP = Symbol("drop connection");

const tlsOptions = (dir) => ({ key: readFileSync(join(dir, "key.pem")), cert: readFileSync(join(dir, "cert.pem")) });

/**
 * Everything that is not the server under test: an Entra tenant and an F&O environment on one HTTPS port the OS
 * picks. `origin` is where they answer, `seen` records what the server sent, `faults` lets a test make Entra or F&O
 * misbehave, `tables` is the F&O data.
 */
export async function startFakeCloud(certDir) {
  const { privateKey, publicKey } = await generateKeyPair("RS256");
  const jwks = { keys: [{ ...(await exportJWK(publicKey)), kid: "test-key", use: "sig", alg: "RS256" }] };
  // handle is hoisted and runs for requests only, which come once the origin below is known.
  const server = createHttpsServer(tlsOptions(certDir), handle);
  const origin = `https://localhost:${await listenOn(server)}`;
  const issuer = `${origin}/${tenantId}/v2.0`;
  const foUrl = origin;
  /** The F&O resources Entra issues tokens for: the fake's own origin, plus any origin from listenUntrusted or acceptFoOrigin. */
  const foScopes = new Set([`${foUrl}/.default`]);
  /**
   * Application ID URIs of the server's app registration besides api://<client id>. Entra takes each as the audience of
   * an on-behalf-of assertion as well. A test of MCP_AUDIENCE adds its value.
   */
  const identifierUris = new Set();
  /** The other HTTPS servers of listenUntrusted, closed with this one. */
  const untrusted = [];
  /** /data requests the fake is answering now, and the most at one time since the last reset. */
  const load = { data: 0, peakData: 0 };
  const entraCodes = new Map(); // code -> { codeChallenge, redirectUri, user, scope }
  const refreshTokens = new Map(); // refresh token -> { user, scope }
  const users = {
    alice: { upn: "alice@example.com", name: "Alice Admin", roles: ["FO.Write"] }, // carries the app role a write role test asks for
    bob: { upn: "bob@example.com", name: "Bob Clerk" },
    carol: { email: "carol@outlook.com", name: "Carol Personal" }, // a personal Microsoft account in the tenant
    dave: { upn: "dave@example.com", name: "Dave Short", expiresIn: 2 }, // Entra tokens that expire within the test
    eve: { upn: "eve@example.com", name: "Eve Nobody" }, // signs in to Entra but has no F&O user
    frank: { upn: "frank@example.com", name: "Frank Narrow" }, // has an F&O user whose role cannot read LegalEntities
    ghost: { upn: "ghost@example.com", name: "Ghost NoOid", noOid: true }, // Entra issues tokens without an oid claim
  };
  const seen = { authorizeRequests: [], oboScopes: [], foRequests: [], tokenGrants: [], redirected: [] };
  const faults = {
    refreshOutages: 0, // refresh requests Entra fails with refreshOutageStatus before it works again
    refreshOutageStatus: 503,
    refreshDelayMs: 0, // how long a refresh takes
    refreshRefusals: 0, // refresh requests Entra answers with 400 invalid_grant (a revoked or expired grant)
    refreshAs: undefined, // the user Entra answers the next refresh for in place of the one who signed in, as a mixed up token cache would
    metadataDelayMs: 0, // how long /Metadata requests take, for cancel and budget tests
    dataDelayMs: 0, // how long /data requests take
    foStatus: undefined, // when set, every F&O request answers this status
    foBody: undefined, // and this body (a string is sent as text, for HTML error pages)
    foHeaders: undefined, // and these response headers, for example a location for a redirect
    throttle: undefined, // { count, status, retryAfter, method }: the next count /data requests (of that method) answer status, 429 by default, with this Retry-After
    dropConnections: 0, // /data requests whose connection the fake closes without an answer, after it read the request
    dropPatches: 0, // PATCH requests whose connection the fake closes without an answer, after it applied the change
    ignorePatchFields: [], // fields a PATCH accepts but does not store, like business logic that overrides a value
    afterPatch: undefined, // called after every PATCH the fake applied, the answer waits for a promise it returns
    dataEntitiesPadBytes: 0, // makes /Metadata/DataEntities this much bigger, for the size limit of Metadata answers
    filterRows: undefined, // (filter, rows, collection) => { rows } or { error: [status, body] }: replaces the fake's own $filter evaluation
    bigRows: 90, // rows of 100 KB that /data/BigRows answers, 90 make about 9 MB
    emptyCreate: false, // a create stores the record but answers 204 without it, as F&O does for Prefer: return=minimal
    entraRedirects: [], // Entra endpoints ("token", "keys", "discovery") that answer 307 to /elsewhere, which records what arrives there
    readBy: true, // the first CustomersV3 row of a query carries ReadBy, the F&O identity that read it; real F&O has no such field
    beforeCreate: undefined, // (collection, record) => undefined or [status, body]: may change a record before it is stored, for example to assign a number sequence key, or refuse it
  };
  let tables = seedTables();
  let enums = structuredClone(ENUMS);

  /** Signs the claims as the tenant. An exp claim is kept, for a token that is expired already, otherwise the token lives an hour. */
  async function signToken(claims, audience) {
    return new SignJWT(claims).setProtectedHeader({ alg: "RS256", kid: "test-key" }).setIssuer(issuer).setAudience(audience).setIssuedAt().setExpirationTime(claims.exp ?? "1h").sign(privateKey);
  }

  /** A delegated user token as Entra issues it for the server's API. An override of undefined leaves that claim out. */
  async function userToken(user, audience, overrides = {}) {
    const { upn, email, name, roles, noOid } = users[user];
    // A personal Microsoft account in the tenant has no preferred_username or upn in a v1 token, only email and unique_name.
    const identity = upn ? { preferred_username: upn } : { email, unique_name: `live.com#${email}`, idp: "live.com" };
    const claims = { ...identity, name, ...(noOid ? {} : { oid: `oid-${user}` }), tid: tenantId, scp: "access_as_user", azp: clientId, ...(roles ? { roles } : {}), ...overrides };
    for (const k of Object.keys(claims)) if (claims[k] === undefined) delete claims[k];
    return signToken(claims, audience);
  }

  /** An app-only token for the server's audience, what a service principal of the tenant could get. It has no user and no scp. */
  async function appToken(audience) {
    return signToken({ oid: "oid-some-app", tid: tenantId, roles: [], azp: "11111111-0000-0000-0000-000000000000" }, audience);
  }

  /** A token signed by a key the tenant does not publish, or with a wrong issuer or audience, for negative tests. */
  async function foreignToken(audience, { wrongIssuer = false } = {}) {
    const other = await generateKeyPair("RS256");
    return new SignJWT({ preferred_username: "mallory@example.com", oid: "oid-mallory", tid: tenantId, scp: "access_as_user", azp: clientId })
      .setProtectedHeader({ alg: "RS256", kid: "test-key" }).setIssuer(wrongIssuer ? "https://evil.example/v2.0" : issuer).setAudience(audience)
      .setIssuedAt().setExpirationTime("1h").sign(wrongIssuer ? privateKey : other.privateKey);
  }

  /** What Entra does when the browser arrives at /authorize: sign the user in and send the browser back with a code. */
  function authorize(params, user) {
    seen.authorizeRequests.push(Object.fromEntries(params));
    assert.equal(params.get("client_id"), clientId, "the server must sign users in with its own app registration");
    assert.equal(params.get("code_challenge_method"), "S256", "the server must use PKCE towards Entra");
    // The server asks for a scope of its own API as <client id>/<name>, the name of MCP_SCOPE, access_as_user by default.
    // The tokens of the sign in then carry that name in scp.
    const scope = params.get("scope").split(" ").find((s) => s.startsWith(`${clientId}/`))?.slice(clientId.length + 1);
    assert.ok(scope, `the server must ask for a scope of its own API, got scope=${params.get("scope")}`);
    // Codes for personal Microsoft accounts are long, past 2,000 characters in practice.
    const code = `entra-code-${random()}${users[user].email ? "x".repeat(3000) : ""}`;
    entraCodes.set(code, { codeChallenge: params.get("code_challenge"), redirectUri: params.get("redirect_uri"), user, scope });
    const back = new URL(params.get("redirect_uri"));
    back.searchParams.set("code", code);
    back.searchParams.set("state", params.get("state"));
    return back.toString();
  }

  async function token(form) {
    if (form.get("client_id") !== clientId || form.get("client_secret") !== clientSecret) return [401, { error: "invalid_client", error_description: "wrong client id or secret" }];
    const grant = form.get("grant_type");
    seen.tokenGrants.push(grant);
    let user, scope;
    if (grant === "client_credentials") {
      // The local server: an app token for F&O, F&O maps the client ID to a user.
      if (!foScopes.has(form.get("scope"))) return [400, { error: "invalid_scope", error_description: `unexpected scope ${form.get("scope")}` }];
      return [200, { token_type: "Bearer", access_token: "fo-token-for-service", expires_in: 3600 }];
    } else if (grant === "authorization_code") {
      const issued = entraCodes.get(form.get("code"));
      entraCodes.delete(form.get("code"));
      if (!issued) return [400, { error: "invalid_grant", error_description: "unknown code" }];
      if (issued.redirectUri !== form.get("redirect_uri")) return [400, { error: "invalid_grant", error_description: "redirect_uri mismatch" }];
      if (s256(form.get("code_verifier") ?? "") !== issued.codeChallenge) return [400, { error: "invalid_grant", error_description: "PKCE verifier mismatch" }];
      ({ user, scope } = issued);
    } else if (grant === "refresh_token") {
      if (faults.refreshDelayMs) await sleep(faults.refreshDelayMs);
      if (faults.refreshOutages > 0) {
        faults.refreshOutages--;
        return [faults.refreshOutageStatus, { error: "temporarily_unavailable", error_description: "Entra is having a bad day" }];
      }
      if (faults.refreshRefusals > 0) {
        faults.refreshRefusals--;
        // Entra ends its error descriptions with lines that only identify the request.
        return [400, { error: "invalid_grant", error_description: `AADSTS70043: The refresh token has expired or is invalid\r\nTrace ID: ${ENTRA_TRACE}\r\nCorrelation ID: ${ENTRA_TRACE}\r\nTimestamp: 2026-10-09 10:00:00Z` }];
      }
      // Like Entra for a confidential client, a refresh token stays valid after it was used.
      const signedIn = refreshTokens.get(form.get("refresh_token"));
      if (!signedIn) return [400, { error: "invalid_grant", error_description: "unknown refresh token" }];
      ({ user, scope } = signedIn);
      if (faults.refreshAs) {
        user = faults.refreshAs;
        faults.refreshAs = undefined;
      }
    } else if (grant === "urn:ietf:params:oauth:grant-type:jwt-bearer") {
      // On-behalf-of: the assertion must be a token this tenant issued for the server's app, the scope must name F&O.
      if (form.get("requested_token_use") !== "on_behalf_of") return [400, { error: "invalid_request", error_description: "requested_token_use" }];
      seen.oboScopes.push(form.get("scope"));
      if (!foScopes.has(form.get("scope"))) return [400, { error: "invalid_scope", error_description: `unexpected scope ${form.get("scope")}` }];
      let payload;
      try {
        ({ payload } = await jwtVerify(form.get("assertion"), publicKey, { issuer, audience: [clientId, `api://${clientId}`, ...identifierUris] }));
      } catch (error) {
        return [400, { error: "invalid_grant", error_description: `assertion rejected: ${error.message}` }];
      }
      return [200, { token_type: "Bearer", access_token: `fo-token-for-${payload.preferred_username ?? payload.email}`, expires_in: 3600 }];
    } else {
      return [400, { error: "unsupported_grant_type" }];
    }
    const refresh = `entra-refresh-${random()}`;
    refreshTokens.set(refresh, { user, scope });
    return [200, { token_type: "Bearer", access_token: await userToken(user, clientId, { scp: scope }), refresh_token: refresh, expires_in: users[user].expiresIn ?? 3600, scope: `${clientId}/${scope}` }];
  }

  /** The type name F&O uses in its OData messages, for example Microsoft.Dynamics.DataEntities.CustomerGroup. */
  const typeOf = (collection) => `Microsoft.Dynamics.DataEntities.${PUBLIC_ENTITIES[collection].Name}`;
  const companySpecific = (collection) => PUBLIC_ENTITIES[collection]?.Properties.some((p) => p.Name === "dataAreaId");
  const escapeRegExp = (text) => text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

  /** F&O's string eq: case insensitive, and a * matches any run of characters. */
  const like = (value, pattern) => new RegExp(`^${pattern.split("*").map(escapeRegExp).join(".*")}$`, "is").test(String(value ?? ""));

  /**
   * The clauses of a filter that is only Field eq 'text' joined with and, each optionally in parentheses, as [field, text]
   * pairs. Undefined for any other filter, of which the fake only understands a dataAreaId eq clause.
   */
  function simpleClauses(filter) {
    if (!filter) return [];
    const literals = [];
    const masked = filter.replace(/'((?:[^']|'')*)'/g, (_, text) => `'${literals.push(text.replace(/''/g, "'")) - 1}'`);
    const clauses = [];
    for (let part of masked.split(/\s+and\s+/i)) {
      part = part.trim();
      while (part.startsWith("(") && part.endsWith(")")) part = part.slice(1, -1).trim();
      const match = /^(\w+) eq '(\d+)'$/.exec(part);
      if (!match) return undefined;
      clauses.push([match[1], literals[Number(match[2])]]);
    }
    return clauses;
  }

  /** A 400 like the one F&O answers for a $select with a name the entity does not have, or undefined when every name is known. */
  function unknownSelect(collection, select) {
    const { Properties, NavigationProperties } = PUBLIC_ENTITIES[collection];
    const known = (n) => n === "*" || Properties.some((p) => p.Name === n) || NavigationProperties.some((p) => p.Name === n);
    const unknown = select.split(",").map((s) => s.trim()).find((n) => !known(n));
    return unknown ? [400, { error: { code: "", message: `Could not find a property named '${unknown}' on type '${typeOf(collection)}'.` } }] : undefined;
  }

  /** Keep only the selected fields of a row, its annotations and an expanded navigation property. */
  function applySelect(row, select, expanded) {
    const names = select.split(",").map((s) => s.trim());
    if (names.includes("*")) return row;
    return Object.fromEntries(Object.entries(row).filter(([k]) => k.startsWith("@") || names.includes(k) || k === expanded));
  }

  /** A 400 like the one OData answers for a body with a property the entity does not have, or undefined when every property is known. */
  function unknownProperty(collection, record) {
    const unknown = Object.keys(record).find((k) => !k.startsWith("@") && !PUBLIC_ENTITIES[collection].Properties.some((p) => p.Name === k));
    return unknown
      ? [400, { error: { code: "", message: `The property '${unknown}' does not exist on type '${typeOf(collection)}'. Make sure to only use property names that are defined by the type.` } }]
      : undefined;
  }

  /** The 400 of CustGroup.validateWrite for a terms of payment that does not exist, or undefined when it does. */
  function unknownPaymentTerm(record) {
    if (record.PaymentTermId === undefined || PAYMENT_TERMS.includes(record.PaymentTermId)) return undefined;
    return [400, writeFailed("CustGroup", `Terms of payment ${record.PaymentTermId} does not exist.`)];
  }

  /**
   * The rows of a collection after the query options the fake understands: a filter of eq clauses joined with and
   * (any other filter only for its dataAreaId eq clause), $top, $skip, $select, $expand of SalesOrderLines and $count.
   */
  function query(collection, params, user) {
    let rows = (tables[collection] ?? []).map((r) => ({ "@odata.etag": `W/"${random()}"`, ...structuredClone(r) }));
    const filter = params.get("$filter") ?? "";
    let company;
    if (faults.filterRows) {
      // An evaluator of the caller's own, for example one that understands or and answers F&O's errors for what F&O rejects.
      const evaluated = faults.filterRows(filter, rows, collection);
      if (evaluated.error) return evaluated.error;
      rows = evaluated.rows;
      company = /dataAreaId eq '([^']*)'/.exec(filter)?.[1];
    } else {
      const clauses = simpleClauses(filter);
      company = clauses ? clauses.find(([name]) => name === "dataAreaId")?.[1] : /dataAreaId eq '([^']*)'/.exec(filter)?.[1];
      if (clauses) rows = rows.filter((r) => clauses.every(([name, text]) => like(r[name], text)));
      else if (company) rows = rows.filter((r) => r.dataAreaId === company.toLowerCase());
    }
    if (!company && companySpecific(collection) && params.get("cross-company") !== "true") {
      rows = rows.filter((r) => r.dataAreaId === "dat"); // like F&O: without cross-company only the user's default company, which is empty
    }
    const select = params.get("$select");
    if (select && unknownSelect(collection, select)) return unknownSelect(collection, select);
    const total = rows.length;
    const skip = Number(params.get("$skip") ?? 0);
    const top = params.has("$top") ? Number(params.get("$top")) : rows.length;
    rows = rows.slice(skip, skip + top);
    const expanded = (params.get("$expand") ?? "").startsWith("SalesOrderLines") && collection === "SalesOrderHeadersV2" ? "SalesOrderLines" : undefined;
    if (expanded) {
      for (const r of rows) r.SalesOrderLines = tables.SalesOrderLines.filter((l) => l.SalesOrderNumber === r.SalesOrderNumber && l.dataAreaId === r.dataAreaId);
    }
    if (select) rows = rows.map((r) => applySelect(r, select, expanded));
    if (faults.readBy && collection === "CustomersV3" && rows[0]) rows[0].ReadBy = user; // lets tests see which F&O identity read the data
    return [200, { ...(params.get("$count") === "true" ? { "@odata.count": total } : {}), value: rows }];
  }

  /** Parse the key of /data/Collection(dataAreaId='USMF',CustomerGroupId='10'). */
  function parseKey(text) {
    return Object.fromEntries([...text.matchAll(/(\w+)=(?:'((?:[^']|'')*)'|([^,]+))/g)].map((m) => [m[1], m[2] !== undefined ? m[2].replace(/''/g, "'") : m[3]]));
  }

  /** What /Metadata/PublicEnumerations answers for one enum. */
  const enumeration = (name) => ({
    Name: name, LabelId: `@TST_${name}`,
    Members: enums[name].map((member, i) => ({ Name: member, LabelId: `@TST_${name}_${member}`, Value: i, ConfigurationEnabled: true })),
  });

  async function fo(req, body) {
    const user = /^Bearer fo-token-for-(.+)$/.exec(req.headers.authorization ?? "")?.[1];
    if (!user) return [401, { Message: "Authorization has been denied for this request." }];
    const url = new URL(req.url, origin);
    seen.foRequests.push({ user, method: req.method, path: decodeURIComponent(url.pathname) + decodeURIComponent(url.search), body: body || undefined, agent: req.headers["user-agent"] });
    if (url.pathname.startsWith("/Metadata/") && faults.metadataDelayMs) await sleep(faults.metadataDelayMs);
    if (url.pathname.startsWith("/data/") && faults.dataDelayMs) await sleep(faults.dataDelayMs);
    if (url.pathname.startsWith("/data/") && faults.dropConnections > 0) {
      faults.dropConnections--;
      return DROP;
    }
    if (url.pathname.startsWith("/data/") && faults.throttle?.count > 0 && (!faults.throttle.method || faults.throttle.method === req.method)) {
      faults.throttle.count--;
      const retryAfter = faults.throttle.retryAfter;
      return [faults.throttle.status ?? 429, { Message: "Too many requests, try again later." }, retryAfter !== undefined ? { "retry-after": String(retryAfter) } : {}];
    }
    if (faults.foStatus) return [faults.foStatus, faults.foBody ?? { Message: "An error has occurred." }, faults.foHeaders];
    if (user === users.eve.upn) return [403, { Message: "Please verify that the user is valid and set up correctly." }];
    if (user === users.frank.upn && url.pathname === "/data/LegalEntities") {
      return [403, { Message: "An error has occurred.", ExceptionMessage: "User is not authorized to read view LegalEntityEntity.  Request denied." }];
    }
    const path = decodeURIComponent(url.pathname);
    if (req.method === "GET" && path === "/Metadata/DataEntities") {
      const padding = faults.dataEntitiesPadBytes ? [entityRow("PaddingEntity", "Padding", "Paddings", { DataServiceEnabled: false, LabelId: "x".repeat(faults.dataEntitiesPadBytes) })] : [];
      return [200, { value: [...DATA_ENTITIES, ...padding] }];
    }
    if (req.method === "GET" && path === "/Metadata/PublicEntities") {
      const name = /EntitySetName eq '([^']*)'/.exec(url.searchParams.get("$filter") ?? "")?.[1];
      return [200, { value: PUBLIC_ENTITIES[name] ? [PUBLIC_ENTITIES[name]] : [] }];
    }
    const label = /^\/Metadata\/Labels\(Id='((?:[^']|'')*)',Language='([^']*)'\)$/.exec(path);
    if (req.method === "GET" && label) {
      const id = label[1].replace(/''/g, "'");
      if (!id.startsWith("@TST_")) return [404, { Message: "No label" }];
      return [200, { Id: id, Language: label[2], Value: `${id.slice(5)} (${label[2]})` }];
    }
    const enumName = /^\/Metadata\/PublicEnumerations\('([^']*)'\)$/.exec(path)?.[1];
    if (req.method === "GET" && enumName !== undefined) {
      return enums[enumName] ? [200, enumeration(enumName)] : [404, { Message: `No HTTP resource was found that matches the request URI '${url}'.` }];
    }
    if (req.method === "GET" && path === "/Metadata/PublicEnumerations") {
      const name = /Name eq '([^']*)'/.exec(url.searchParams.get("$filter") ?? "")?.[1];
      return [200, { value: enums[name] ? [enumeration(name)] : [] }];
    }
    if (req.method === "POST" && path === "/data/DataManagementEntities/Microsoft.Dynamics.DataEntities.GetApplicationVersion") return [200, { value: "10.0.48" }];
    if (req.method === "POST" && path === "/data/DocumentRoutingClientApps/Microsoft.Dynamics.DataEntities.GetPlatformVersion") return [200, { value: "7.0.7521.0" }];
    if (req.method === "GET" && path === "/data/BigRows") {
      // About 9 MB by default, over the server's 4 MB limit for one /data answer.
      const payload = "x".repeat(100_000);
      return [200, { value: Array.from({ length: faults.bigRows }, (_, i) => ({ Id: String(i), Payload: payload })) }];
    }
    const collection = /^\/data\/(\w+)$/.exec(path)?.[1];
    if (req.method === "GET" && collection && tables[collection]) return query(collection, url.searchParams, user);
    if (req.method === "POST" && collection && tables[collection]) {
      const record = JSON.parse(body || "{}");
      const refused = unknownProperty(collection, record) ?? (collection === "CustomerGroups" ? unknownPaymentTerm(record) : undefined);
      if (refused) return refused;
      const hooked = faults.beforeCreate?.(collection, record);
      if (hooked) return hooked;
      if (collection === "CustomerGroups") {
        if (!record.CustomerGroupId) return [400, { Message: "An error has occurred.", ExceptionMessage: "Field validation failed on table of type 'CustCustomerGroupEntity': Customer group must be filled in." }];
        if (tables.CustomerGroups.some((g) => g.CustomerGroupId === record.CustomerGroupId && g.dataAreaId === String(record.dataAreaId).toLowerCase())) {
          return [400, { Message: "An error has occurred.", ExceptionMessage: `Customer group ${record.CustomerGroupId} already exists.` }];
        }
      }
      const row = {
        ...(collection === "CustomerGroups" ? { ClearingPeriodPaymentTermName: "" } : {}),
        ...record,
        ...(companySpecific(collection) ? { dataAreaId: String(record.dataAreaId ?? "dat").toLowerCase() } : {}),
      };
      tables[collection].push(row);
      if (faults.emptyCreate) return [204, undefined];
      return [201, { "@odata.etag": 'W/"1"', ...row }];
    }
    const keyed = /^\/data\/(\w+)\((.*)\)$/.exec(path);
    if (keyed && tables[keyed[1]] && (req.method === "GET" || req.method === "PATCH")) {
      const [, name, keyText] = keyed;
      const key = parseKey(keyText);
      // Like F&O: without cross-company=true a key in another company than the user's own is not found.
      const outside = companySpecific(name) && url.searchParams.get("cross-company") !== "true" && String(key.dataAreaId).toLowerCase() !== "dat";
      const row = outside ? undefined : tables[name].find((r) => Object.entries(key).every(([k, v]) => String(r[k]).toLowerCase() === String(v).toLowerCase()));
      if (req.method === "GET") {
        if (!row) return [404, { error: { code: "", message: `Resource not found for the segment '${name}'.` } }];
        const select = url.searchParams.get("$select");
        if (select && unknownSelect(name, select)) return unknownSelect(name, select);
        const record = { "@odata.etag": `W/"${random()}"`, ...structuredClone(row) };
        return [200, select ? applySelect(record, select) : record];
      }
      if (!row) return [404, { Message: "No resources were found when selecting for update." }];
      const changes = JSON.parse(body || "{}");
      const refused = unknownProperty(name, changes) ?? (name === "CustomerGroups" ? unknownPaymentTerm(changes) : undefined);
      if (refused) return refused;
      for (const field of faults.ignorePatchFields) delete changes[field];
      Object.assign(row, changes);
      await faults.afterPatch?.();
      if (faults.dropPatches > 0) {
        faults.dropPatches--;
        return DROP;
      }
      return [204, undefined];
    }
    return [404, { Message: `No HTTP resource was found that matches the request URI '${url}'.` }];
  }

  /** Every request of the fake, on its own port and on the ports of listenUntrusted. */
  function handle(req, res) {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", async () => {
      const body = Buffer.concat(chunks).toString("utf8");
      const url = new URL(req.url, origin);
      let status = 404;
      let json = { error: "not_found", path: url.pathname };
      let headers = {};
      const redirected = { [`/${tenantId}/oauth2/v2.0/token`]: "token", [`/${tenantId}/discovery/v2.0/keys`]: "keys", [`/${tenantId}/v2.0/.well-known/openid-configuration`]: "discovery" }[url.pathname];
      if (faults.entraRedirects.includes(redirected)) {
        // A 307 keeps the method and the body, so a client that follows it sends the client secret on to /elsewhere.
        res.writeHead(307, { location: `${origin}/elsewhere` }).end();
        return;
      }
      if (url.pathname === "/elsewhere") {
        seen.redirected.push({ method: req.method, body });
        res.writeHead(404, { "content-type": "application/json" }).end(JSON.stringify({ error: "not_found" }));
        return;
      }
      try {
        if (url.pathname === `/${tenantId}/v2.0/.well-known/openid-configuration`) [status, json] = [200, { issuer, jwks_uri: `${origin}/${tenantId}/discovery/v2.0/keys` }];
        else if (url.pathname === `/${tenantId}/discovery/v2.0/keys`) [status, json] = [200, jwks];
        else if (url.pathname === `/${tenantId}/oauth2/v2.0/authorize`) {
          res.writeHead(302, { location: authorize(url.searchParams, "alice") }).end();
          return;
        } else if (url.pathname === `/${tenantId}/oauth2/v2.0/token`) [status, json] = await token(new URLSearchParams(body));
        else if (url.pathname.startsWith("/data/") || url.pathname.startsWith("/Metadata/")) {
          const data = url.pathname.startsWith("/data/");
          if (data) load.peakData = Math.max(load.peakData, ++load.data);
          let answer;
          try {
            answer = await fo(req, body);
          } finally {
            if (data) load.data--;
          }
          if (answer === DROP) {
            req.socket.destroy();
            return;
          }
          [status, json, headers = {}] = answer;
        }
      } catch (error) {
        [status, json] = [500, { error: "fake_cloud_failed", error_description: error.message }];
      }
      if (res.destroyed) return;
      if (json === undefined) res.writeHead(status, headers).end();
      else if (typeof json === "string") res.writeHead(status, { "content-type": "text/html", ...headers }).end(json);
      else res.writeHead(status, { "content-type": "application/json", ...headers }).end(JSON.stringify(json));
    });
  }

  return {
    origin, foUrl, issuer, users, seen, faults, identifierUris, authorize, userToken, appToken, foreignToken,
    get tables() { return tables; },
    /** The enums by name, as element names. A server caches them for ten minutes, so a test that changes one needs a fresh server. */
    get enums() { return enums; },
    /** The most /data requests the fake answered at one time since the last reset. */
    get peakDataRequests() { return load.peakData; },
    /**
     * Serve the same fake on another port under the certificate of otherCertDir, one that serverEnv does not make the
     * servers under test trust. With FO_URL pointed there, F&O is reachable only with FO_CA_FILE or FO_INSECURE_TLS=1,
     * so a test can see whether certificate validation towards F&O is on. Returns the origin, which Entra also takes as
     * an F&O resource.
     */
    async listenUntrusted(otherCertDir) {
      const other = createHttpsServer(tlsOptions(otherCertDir), handle);
      const otherOrigin = `https://localhost:${await listenOn(other)}`;
      untrusted.push(other);
      foScopes.add(`${otherOrigin}/.default`);
      return otherOrigin;
    },
    /**
     * Let Entra issue F&O tokens for another origin that reaches this fake, for example a host name that only
     * FO_HOST_IP resolves to its address. The port stays the fake's own.
     */
    acceptFoOrigin(otherOrigin) {
      foScopes.add(`${otherOrigin}/.default`);
    },
    /** Put the F&O data, the faults and the record of requests back to the start. */
    reset() {
      tables = seedTables();
      enums = structuredClone(ENUMS);
      load.peakData = load.data;
      Object.assign(faults, {
        refreshOutages: 0, refreshOutageStatus: 503, refreshDelayMs: 0, refreshRefusals: 0, refreshAs: undefined, metadataDelayMs: 0, dataDelayMs: 0, foStatus: undefined,
        foBody: undefined, foHeaders: undefined, throttle: undefined, dropConnections: 0, dropPatches: 0, ignorePatchFields: [], afterPatch: undefined, dataEntitiesPadBytes: 0,
        filterRows: undefined, bigRows: 90, emptyCreate: false, entraRedirects: [], readBy: true, beforeCreate: undefined,
      });
      for (const k of Object.keys(seen)) seen[k].length = 0;
    },
    close: () => Promise.all([server, ...untrusted].map((s) => new Promise((resolve) => { s.closeAllConnections?.(); s.close(resolve); }))),
  };
}

// ---------------------------------------------------------------- Servers under test

let builtVariables;

/**
 * Every FO_ and MCP_ variable the built server mentions, in any file of dist. The server fills an unset one from the .env
 * next to its package.json, so each one must be set for a server under test. Read once, when the first server starts.
 */
export function serverVariables() {
  const dist = join(projectDir, "dist");
  builtVariables ??= [...new Set(readdirSync(dist).filter((f) => f.endsWith(".js")).flatMap((f) => readFileSync(join(dist, f), "utf8").match(/\b(?:FO|MCP)_[A-Z0-9_]+\b/g) ?? []))];
  return builtVariables;
}

/**
 * Environment for a server against the fake cloud. Empty values win over the developer's .env, loadConfig treats them as
 * unset. A .env that follows README's advice for a real server, MCP_TRUST_PROXY=0 behind no proxy for example, must not
 * change what the tests see, so every variable the server reads is set, empty unless a test gives it a value.
 */
export function serverEnv(cloud, certFile, overrides = {}) {
  return {
    PATH: process.env.PATH,
    ...Object.fromEntries(serverVariables().map((name) => [name, ""])),
    // loadProjectEnv copies .env into process.env and Node reads this variable at every TLS connection, so a .env line
    // would turn the certificate checks off for the servers under test. Blank, it is set and the .env cannot fill it.
    NODE_TLS_REJECT_UNAUTHORIZED: "",
    // Trusts the fake's certificate on its own port, for Entra and F&O alike. FO_INSECURE_TLS below changes nothing
    // there, the tests of certificate validation point FO_URL at cloud.listenUntrusted instead.
    NODE_EXTRA_CA_CERTS: certFile,
    FO_URL: cloud.foUrl,
    FO_AUTHORITY: cloud.origin,
    FO_TENANT_ID: tenantId,
    FO_CLIENT_ID: clientId,
    FO_CLIENT_SECRET: clientSecret,
    FO_COMPANY: "USMF",
    FO_ALLOW_WRITES: "0",
    FO_INSECURE_TLS: "1",
    // A proxy from the developer's .env must not route the fake cloud traffic. undici reads the lowercase names first.
    HTTPS_PROXY: "", https_proxy: "", HTTP_PROXY: "", http_proxy: "", NO_PROXY: "", no_proxy: "",
    ...overrides,
  };
}

/**
 * Start dist/http.js, or the copy of it given as script, against the fake cloud and wait until it wrote its start
 * line and /health answers. Without `port` the
 * server gets a free one, which the result names as `port` and in `url`. freePort reserves nothing, so a server of a
 * test file running at the same time can take that port first: the child then fails to bind and is started again on
 * another one, up to three times. A `port` given is the caller's own, in MCP_PUBLIC_URL for example, so a server that
 * cannot bind it fails with its log. `pickPort` is for the test of the retry.
 */
export async function startServer({ port, cloud, certFile, env = {}, script = join(projectDir, "dist/http.js"), pickPort = freePort }) {
  let log = "";
  for (let attempt = 1; ; attempt++) {
    const chosen = port ?? (await pickPort());
    const child = spawn(process.execPath, [script], { env: serverEnv(cloud, certFile, { MCP_PORT: String(chosen), ...env }), cwd: projectDir, stdio: ["ignore", "pipe", "pipe"] });
    child.stdout.on("data", (d) => (log += d));
    child.stderr.on("data", (d) => (log += d));
    const exited = new Promise((resolve) => child.on("exit", (code, signal) => resolve(code ?? signal)));
    const closed = new Promise((resolve) => child.on("close", resolve));
    const deadline = Date.now() + 15_000;
    const before = log.length;
    while (Date.now() < deadline) {
      if (child.exitCode !== null) break;
      // /health of this port says nothing about who answers. When the port was taken by a server of another test file,
      // that one answers 200 within a millisecond, long before the child fails to bind. Only the child's own start line
      // says that it holds the port, and until it is there the poll goes on so that the child's exit is seen.
      if (log.slice(before).includes(` listening on `)) {
        try {
          // With a timeout: whatever holds the port may accept the connection and never answer.
          const r = await fetch(`http://localhost:${chosen}/health`, { signal: AbortSignal.timeout(1000) });
          if (r.ok) return { child, exited, log: () => log, stop: () => { child.kill(); return exited; }, url: `http://localhost:${chosen}/mcp`, port: chosen };
          log += `health ${r.status} ${await r.text()}\n`;
        } catch (error) {
          log += `health poll: ${error.message} ${error.cause?.message ?? ""}\n`;
        }
      }
      await sleep(50);
    }
    child.kill();
    if (port === undefined && attempt < 3 && child.exitCode !== null) {
      // The child ended on its own. Its last output arrives with close, and a taken port is the one failure worth another go.
      await closed;
      if (log.slice(before).includes("EADDRINUSE")) {
        log += `fo-mcp could not bind port ${chosen}, starting again on another one\n`;
        continue;
      }
    }
    throw new Error(`fo-mcp did not start:\n${log}`);
  }
}

/** Start the local stdio server (dist/index.js) against the fake cloud and connect an MCP client to it. */
export async function startStdio({ cloud, certFile, env = {} }) {
  const transport = new StdioClientTransport({ command: process.execPath, args: [join(projectDir, "dist/index.js")], cwd: projectDir, env: serverEnv(cloud, certFile, env), stderr: "pipe" });
  let log = "";
  transport.stderr?.on("data", (d) => (log += d));
  const client = new Client({ name: "stdio-test", version: "0.0.0" });
  await client.connect(transport);
  // The SDK keeps the server process to itself, only its pid is public. The tests of a signal to the local server need
  // the process for its exit code, so it is taken from where the SDK holds it.
  const child = transport._process;
  const exited = new Promise((resolve) => child.on("exit", (code, signal) => resolve(code ?? signal)));
  return { client, child, exited, log: () => log, close: () => client.close() };
}

// ---------------------------------------------------------------- Client side

/** A random private address, for the X-Forwarded-For header that stands for the client's address at the server. */
export const randomIp = () => `10.${randomBytes(1)[0]}.${randomBytes(1)[0]}.${randomBytes(1)[0]}`;

/**
 * A browser for the server's sign in pages: it keeps the cookies the server sets by name and path, sends them back like
 * a browser does and never follows redirects. Every request comes from a new address unless `ip` is given, so the
 * limits per address only apply in the tests that are about them.
 */
export function makeBrowser({ ip } = {}) {
  const jar = new Map(); // name -> { value, path, attributes }
  const history = []; // "METHOD /path status" of every request
  const matches = (path, cookiePath) => path === cookiePath || path.startsWith(cookiePath.endsWith("/") ? cookiePath : `${cookiePath}/`);
  return {
    jar,
    history,
    ip,
    /** The cookies the server set with all their attributes, by name. */
    cookie: (name) => jar.get(name),
    async fetch(url, init = {}) {
      const target = new URL(url);
      const cookie = [...jar].filter(([, c]) => matches(target.pathname, c.path)).map(([name, c]) => `${name}=${c.value}`).join("; ");
      const headers = { "x-forwarded-for": ip ?? randomIp(), ...(cookie ? { cookie } : {}), ...init.headers };
      const response = await fetch(url, { redirect: "manual", ...init, headers });
      history.push(`${init.method ?? "GET"} ${target.pathname} ${response.status}`);
      for (const line of response.headers.getSetCookie()) {
        const [pair, ...rest] = line.split(";").map((p) => p.trim());
        const eq = pair.indexOf("=");
        const attributes = Object.fromEntries(rest.map((a) => [a.split("=")[0].toLowerCase(), a.includes("=") ? a.slice(a.indexOf("=") + 1) : true]));
        const name = pair.slice(0, eq);
        const expired = attributes["max-age"] !== undefined ? Number(attributes["max-age"]) <= 0 : attributes.expires !== undefined && Date.parse(attributes.expires) <= Date.now();
        if (expired) jar.delete(name);
        else jar.set(name, { value: pair.slice(eq + 1), path: attributes.path ?? "/", attributes });
      }
      return response;
    },
  };
}

/** The headers every page of the server carries, and nothing else may be set on them. */
export const PAGE_HEADERS = {
  "content-security-policy": "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'",
  "x-frame-options": "DENY",
  "cache-control": "no-store",
  "referrer-policy": "no-referrer",
};

/**
 * Check that a response is one of the server's HTML pages with the given status, not a redirect, and return its text.
 * The consent page alone has Referrer-Policy: same-origin, so the browser sends its origin with the form.
 */
export async function assertPage(response, status, pattern) {
  const html = await response.text();
  assert.equal(response.status, status, html);
  assert.equal(response.headers.get("location"), null, "a page, never a redirect");
  assert.match(response.headers.get("content-type") ?? "", /^text\/html/);
  const consent = html.includes('<form method="post" action="/consent">');
  for (const [name, value] of Object.entries({ ...PAGE_HEADERS, ...(consent ? { "referrer-policy": "same-origin" } : {}) })) {
    assert.equal(response.headers.get(name), value, `${name} of a ${status} page`);
  }
  assert.equal(response.headers.get("access-control-allow-origin"), null, "pages get no CORS headers");
  if (pattern) assert.match(html, pattern);
  return html;
}

/** Wait until the server wrote a log line that contains marker and return it. */
export async function logLine(server, marker) {
  const deadline = Date.now() + 3000;
  while (Date.now() < deadline) {
    const line = server.log().split("\n").find((l) => l.includes(marker));
    if (line) return line;
    await sleep(20);
  }
  assert.fail(`no log line with ${marker} in:\n${server.log()}`);
}

/** The hidden fields of the consent form in a consent page, failing the test when the page has none. */
export function consentForm(html) {
  const value = (name) => new RegExp(`name="${name}" value="([^"]*)"`).exec(html)?.[1];
  const form = { request: value("request"), csrf: value("csrf") };
  assert.ok(form.request && form.csrf, `expected a consent page, got: ${html.slice(0, 500)}`);
  return form;
}

/**
 * Post the consent form of a page the way its buttons do, approve by default. A browser sends the origin of the page
 * with it, which is the public URL's origin when the server sits behind a proxy.
 */
export function postConsent(browser, base, form, action = "approve", { origin = new URL(base).origin } = {}) {
  return browser.fetch(`${base}/consent`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded", origin }, body: new URLSearchParams({ ...form, action }) });
}

/**
 * Open an authorize URL in a browser and approve the consent page when the server shows one. Returns the server's
 * redirect: to Entra after approval, or back to the client for an error.
 */
export async function authorizeInBrowser(browser, authorizeUrl) {
  const response = await browser.fetch(authorizeUrl);
  if (response.status !== 200) return response;
  return postConsent(browser, new URL(authorizeUrl).origin, consentForm(await response.text()));
}

/** Register a client at the server and return its client id. */
export async function registerClient(base, { redirectUris = [clientRedirect], name = "test client" } = {}) {
  const r = await fetch(`${base}/register`, {
    method: "POST", headers: { "content-type": "application/json", "x-forwarded-for": randomIp() }, body: JSON.stringify({ client_name: name, redirect_uris: redirectUris }),
  });
  assert.equal(r.status, 201, await r.clone().text());
  return (await r.json()).client_id;
}

/** The MCP SDK client side of OAuth, with the browser replaced by fetches with a cookie jar and the fake Entra. */
export function makeProvider(cloud, user) {
  const browser = makeBrowser();
  return {
    redirectUrl: clientRedirect,
    clientMetadata: { client_name: "remote test", redirect_uris: [clientRedirect], grant_types: ["authorization_code", "refresh_token"], response_types: ["code"], token_endpoint_auth_method: "none" },
    browser,
    _client: undefined,
    _tokens: undefined,
    _verifier: undefined,
    signIn: undefined,
    clientInformation() { return this._client; },
    saveClientInformation(info) { this._client = info; },
    tokens() { return this._tokens; },
    saveTokens(tokens) { this._tokens = tokens; },
    codeVerifier() { return this._verifier; },
    saveCodeVerifier(v) { this._verifier = v; },
    redirectToAuthorization(url) {
      this.signIn = (async () => {
        // 1. The server shows the consent page, the user approves and the server sends the browser to Entra.
        const toEntra = await authorizeInBrowser(browser, url);
        assert.ok([302, 303].includes(toEntra.status), `authorize must end in a redirect, got ${toEntra.status} ${await toEntra.clone().text()}`);
        const entraUrl = new URL(toEntra.headers.get("location"));
        assert.equal(`${entraUrl.origin}${entraUrl.pathname}`, `${cloud.origin}/${tenantId}/oauth2/v2.0/authorize`);
        // 2. Entra signs the user in and sends the browser to the server's callback.
        const toCallback = cloud.authorize(entraUrl.searchParams, user);
        // 3. The server exchanges the Entra code and sends the browser on to the client with its own code.
        const toClient = await browser.fetch(toCallback);
        assert.equal(toClient.status, 302, "callback must redirect");
        const clientUrl = new URL(toClient.headers.get("location"));
        assert.equal(`${clientUrl.origin}${clientUrl.pathname}`, clientRedirect);
        assert.equal(clientUrl.searchParams.get("error"), null, clientUrl.searchParams.get("error_description") ?? "");
        return clientUrl.searchParams.get("code");
      })();
    },
  };
}

/** Connect an MCP client to the remote server, signing in through the fake Entra when the server asks. */
export async function connectWithSignIn(serverUrl, provider) {
  const client = new Client({ name: "remote-test", version: "0.0.0" });
  // Registration and token requests come from an address of their own too, like the browser's.
  const fetchFrom = (url, init = {}) => {
    const headers = new Headers(init.headers);
    headers.set("x-forwarded-for", randomIp());
    return fetch(url, { ...init, headers });
  };
  const options = { authProvider: provider, fetch: fetchFrom };
  let transport = new StreamableHTTPClientTransport(new URL(serverUrl), options);
  try {
    await client.connect(transport);
  } catch (error) {
    if (!(error instanceof UnauthorizedError)) throw error;
    await transport.finishAuth(await provider.signIn);
    transport = new StreamableHTTPClientTransport(new URL(serverUrl), options);
    await client.connect(transport);
  }
  client.transportInUse = transport;
  return client;
}

export const INITIALIZE = { jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-03-26", capabilities: {}, clientInfo: { name: "t", version: "0" } } };

/** A raw MCP POST, for what the SDK client never sends on purpose. */
export function mcpPost(serverUrl, token, body, sessionId, headers = {}) {
  return fetch(serverUrl, {
    method: "POST",
    headers: { "content-type": "application/json", accept: "application/json, text/event-stream", authorization: `Bearer ${token}`, ...(sessionId ? { "mcp-session-id": sessionId } : {}), ...headers },
    body: JSON.stringify(body),
  });
}

export function refreshAt(port, provider, refreshToken = provider._tokens.refresh_token) {
  return fetch(`http://localhost:${port}/token`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded", "x-forwarded-for": randomIp() },
    body: new URLSearchParams({ grant_type: "refresh_token", refresh_token: refreshToken, client_id: provider._client.client_id }) });
}

/** Call a tool and return its parsed JSON, failing the test when the tool reports an error. */
export async function callTool(client, name, args = {}) {
  const { text, isError } = await callToolRaw(client, name, args);
  assert.equal(isError, false, text);
  return JSON.parse(text);
}

/** Call a tool and return its text and whether it is an error, for tests that expect one. */
export async function callToolRaw(client, name, args = {}, options) {
  const result = await client.callTool({ name, arguments: args }, undefined, options);
  return { text: result.content.map((c) => c.text).join("\n"), isError: !!result.isError };
}
