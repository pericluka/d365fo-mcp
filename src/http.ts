#!/usr/bin/env node
// Remote server: Claude connects over HTTP, the user signs in with Entra and every call runs as that
// user. The server validates the token it receives, exchanges it with the on-behalf-of flow for an F&O
// token of the same user and F&O applies the user's security roles.
import { InvalidTokenError } from "@modelcontextprotocol/sdk/server/auth/errors.js";
import { requireBearerAuth } from "@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js";
import { getOAuthProtectedResourceMetadataUrl, mcpAuthMetadataRouter } from "@modelcontextprotocol/sdk/server/auth/router.js";
import type { AuthInfo } from "@modelcontextprotocol/sdk/server/auth/types.js";
import { hostHeaderValidation } from "@modelcontextprotocol/sdk/server/middleware/hostHeaderValidation.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { isInitializeRequest } from "@modelcontextprotocol/sdk/types.js";
import cors from "cors";
import express, { type NextFunction, type Request, type Response } from "express";
import { createRemoteJWKSet, customFetch, jwtVerify, type JWTPayload } from "jose";
import { createHash, randomUUID } from "node:crypto";
import { fetch } from "undici";
import { insecureTlsWarning, loadProjectEnv, projectDir, version } from "./config.js";
import { FoClient, FoError, FoShared, loadConfig, onBehalfOfTokenSource, type FoConfig } from "./fo.js";
import { clientIp, createOAuthProxy, oneLine, RateLimiter, redirectHost } from "./oauth.js";
import { createFoServer } from "./server.js";

loadProjectEnv();

// ---------------------------------------------------------------- Configuration

const GUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
/** Hosts where plain http is allowed. Not [::1]: the MCP SDK refuses an http issuer there and the server could not start. */
const LOOPBACK_HOSTS = ["localhost", "127.0.0.1"];
/** Listen addresses that only this machine reaches. */
const LOOPBACK_ADDRESS = /^(localhost|127(\.\d{1,3}){3}|::1|\[::1\])$/i;
/** The most a request body may hold, for express.json and in the answer to one that is larger. */
const BODY_LIMIT_KB = 100;
/**
 * How long an idle keep-alive connection stays open. The Container Apps ingress pools its connections to the replica
 * and does not read the Keep-Alive header, so it can write the next request onto a connection the server closes at
 * that moment, which the client sees as a reset. Node's 5 s default makes that the common case for a user who thinks
 * for a few seconds between two tool calls. Longer than the 60 s most proxies keep an idle connection.
 */
const KEEP_ALIVE_MS = 65_000;
/**
 * Clock skew between Entra and this server that a direct token may show in nbf and iat. Entra sets nbf to the time it
 * issued the token, so a server a few seconds behind would refuse every fresh token until it is that old. Microsoft's
 * own libraries allow five minutes. A token past its exp is refused all the same, the bearer middleware checks that.
 */
const CLOCK_TOLERANCE_S = 300;

/** The settings of the remote server on top of FoConfig, checked before anything listens or calls Entra. */
function loadRemoteConfig(env: NodeJS.ProcessEnv, config: FoConfig) {
  const portText = env.MCP_PORT?.trim() || "3000";
  // Number() would take 0x50 or 1e3, and a port of 0 would listen anywhere while the default public URL names port 0.
  const port = Number(portText);
  if (!/^\d{1,5}$/.test(portText) || port < 1 || port > 65535) throw new Error(`MCP_PORT must be a whole number from 1 to 65535, got '${env.MCP_PORT}'`);
  /** The URL clients connect to, also the resource identifier the token must be issued for. */
  let publicUrl: URL;
  try {
    publicUrl = new URL(env.MCP_PUBLIC_URL?.trim() || `http://localhost:${port}/mcp`);
  } catch {
    throw new Error(`MCP_PUBLIC_URL must be an absolute URL such as https://mcp.example.com/mcp, got '${env.MCP_PUBLIC_URL}'`);
  }
  if (publicUrl.protocol !== "https:" && publicUrl.protocol !== "http:") throw new Error(`MCP_PUBLIC_URL must start with https://, got '${publicUrl.href}'`);
  const loopback = LOOPBACK_HOSTS.includes(publicUrl.hostname);
  if (publicUrl.protocol === "http:" && publicUrl.hostname === "[::1]") {
    throw new Error(`MCP_PUBLIC_URL must use localhost or 127.0.0.1 for plain http, the MCP SDK refuses http on [::1], got '${publicUrl.href}'`);
  }
  // Codes, tokens and the consent cookie travel over this URL, so anything that leaves the machine needs TLS.
  if (publicUrl.protocol === "http:" && !loopback) {
    throw new Error(`MCP_PUBLIC_URL must start with https:// unless its host is localhost, got '${publicUrl.href}'`);
  }
  // A server other people sign in to must not send their F&O tokens over a connection whose certificate nobody checks.
  if (config.insecureTls && !config.caFile && !loopback) {
    throw new Error("FO_INSECURE_TLS=1 is only allowed while MCP_PUBLIC_URL is on localhost. Set FO_CA_FILE to the F&O server certificate instead.");
  }
  // NODE_TLS_REJECT_UNAUTHORIZED=0 does the same for every host, Entra included, so it is refused there too.
  if (insecureTlsWarning(env) && !loopback) {
    throw new Error("NODE_TLS_REJECT_UNAUTHORIZED=0 is only allowed while MCP_PUBLIC_URL is on localhost, it turns off certificate validation for Entra and F&O. Remove it and set FO_CA_FILE to the F&O server certificate.");
  }
  // Tokens name the tenant by its ID, in the issuer and in tid. A domain name would match neither.
  if (!GUID.test(config.tenantId)) throw new Error(`FO_TENANT_ID must be the directory (tenant) ID, a GUID, got '${config.tenantId}'`);
  const stateKey = env.MCP_STATE_KEY?.trim() || undefined;
  if (stateKey && stateKey.length < 32) throw new Error("MCP_STATE_KEY must be at least 32 characters, for example the output of openssl rand -base64 32");
  const apps = env.MCP_ALLOWED_CLIENT_APPS?.trim() ?? "";
  // When the variable is empty, the server's own app is accepted on localhost only. Anywhere else its tokens can only come
  // from a public client flow on the hosted app, which must stay off: a device code phishing message would then reach
  // /mcp past the consent page.
  const allowedClientApps =
    apps.toLowerCase() === "none" ? [] : apps ? apps.split(",").map((a) => a.trim().toLowerCase()).filter(Boolean) : loopback ? [config.clientId.toLowerCase()] : [];
  if (apps && allowedClientApps.some((a) => !GUID.test(a))) {
    throw new Error(`MCP_ALLOWED_CLIENT_APPS must be app (client) IDs separated by commas, or none, got '${apps}'`);
  }
  /** What the start line says about tokens that come straight from Entra. */
  const directTokens =
    apps.toLowerCase() === "none" ? "no direct Entra tokens (MCP_ALLOWED_CLIENT_APPS=none)"
    : apps ? `direct Entra tokens of ${allowedClientApps.join(", ")} (MCP_ALLOWED_CLIENT_APPS)`
    : loopback ? "direct Entra tokens of FO_CLIENT_ID, the default on localhost"
    : "no direct Entra tokens, the default off localhost (MCP_ALLOWED_CLIENT_APPS lists the apps to accept)";
  const trust = env.MCP_TRUST_PROXY?.trim() || "1";
  if (!/^\d{1,2}$/.test(trust) || Number(trust) > 10) {
    throw new Error(`MCP_TRUST_PROXY must be the number of proxies in front of the server that append to X-Forwarded-For, 0 to 10, got '${env.MCP_TRUST_PROXY}'`);
  }
  /** Audience of the tokens Claude sends. The app registration exposes it as an API, api://<client id> by default. */
  const audience = env.MCP_AUDIENCE?.trim() || `api://${config.clientId}`;
  /** Scope Claude asks for when the user signs in. */
  const scope = env.MCP_SCOPE?.trim() || `${audience}/access_as_user`;
  // On localhost nobody else should reach the server. Anywhere else a proxy or an ingress in front connects to it.
  const host = env.MCP_HOST?.trim() || (!loopback ? "0.0.0.0" : "127.0.0.1");
  // The default public URL is on localhost, which allows plain http, FO_INSECURE_TLS and direct tokens of the server's
  // own app. The image sets MCP_HOST=0.0.0.0, and docker run publishes on every interface of the host, so without this
  // the network would reach a server with all of that relaxed.
  if (!env.MCP_PUBLIC_URL?.trim() && !LOOPBACK_ADDRESS.test(host)) {
    throw new Error(
      `MCP_PUBLIC_URL must be set while MCP_HOST=${host} makes the server listen beyond this machine, for example https://mcp.example.com/mcp. ` +
        `For a local test set MCP_PUBLIC_URL=http://localhost:${port}/mcp and publish the port on 127.0.0.1 only.`
    );
  }
  const writeRole = env.MCP_WRITE_ROLE?.trim() || undefined;
  /** Settings that work but that README calls unsafe for what the server is set up as, said once at start. */
  const warnings: string[] = [];
  if (loopback && !LOOPBACK_ADDRESS.test(host)) {
    warnings.push(
      `MCP_HOST=${host} makes the server listen beyond this machine while MCP_PUBLIC_URL is on ${publicUrl.hostname}, so the network reaches a ` +
        "server with the localhost defaults: plain http, FO_INSECURE_TLS and direct tokens of FO_CLIENT_ID. Publish the port on 127.0.0.1 only, " +
        `for example docker run -p 127.0.0.1:${port}:${port}.`
    );
  }
  if (!loopback && allowedClientApps.includes(config.clientId.toLowerCase())) {
    warnings.push(
      "MCP_ALLOWED_CLIENT_APPS lists FO_CLIENT_ID, the server's own app. With public client flows on that app, a device code phishing " +
        "message reaches /mcp past the consent page. List a separate test app instead."
    );
  }
  if (!loopback && config.allowWrites && !writeRole) {
    warnings.push("writes are enabled for every user who can sign in. Set MCP_WRITE_ROLE to the app role a user needs for create_record and update_record.");
  }
  return {
    port,
    publicUrl,
    loopback,
    host,
    warnings,
    audience,
    scope,
    stateKey,
    allowedClientApps,
    directTokens,
    /** Proxies in front that append to X-Forwarded-For. 1 is the Container Apps ingress, a WAF or Front Door before it adds one. */
    trustProxy: Number(trust),
    writeRole,
    /** Host names the server answers for, against DNS rebinding: always the public host, plus any extra ones for a proxy or a second domain. */
    allowedHosts: [...new Set([publicUrl.hostname, ...(env.MCP_ALLOWED_HOSTS ?? "").split(",").map((h) => h.trim().toLowerCase()).filter(Boolean)])],
  };
}

let shared: FoShared;
let remote: ReturnType<typeof loadRemoteConfig>;
try {
  const foConfig = loadConfig(process.env, projectDir);
  remote = loadRemoteConfig(process.env, foConfig);
  shared = new FoShared(foConfig);
} catch (error) {
  console.error(`fo-mcp: ${(error as Error).message}`);
  process.exit(1);
}
const { config } = shared;
const { port, host, publicUrl, audience, scope, allowedClientApps, writeRole, allowedHosts, trustProxy } = remote;
// Off localhost loadRemoteConfig refused it already. On localhost it is allowed, but nobody should miss it.
const tlsWarning = insecureTlsWarning();
if (tlsWarning) console.error(tlsWarning);
for (const warning of remote.warnings) console.error(`fo-mcp: ${warning}`);
/** The name of that scope, which every user token must carry. */
const scopeName = scope.slice(scope.lastIndexOf("/") + 1);
if (!scopeName) {
  // A trailing slash would leave an empty name, which no token carries, so every sign in would fail at the end.
  console.error(`fo-mcp: MCP_SCOPE must end in the scope name, for example ${audience}/access_as_user, not ${scope}`);
  process.exit(1);
}
/** The same scope in the GUID form, which Entra accepts when an app requests a token for its own API. */
const entraScope = `${config.clientId}/${scopeName}`;
const origin = publicUrl.origin;
const oauth = createOAuthProxy({ shared, origin, scope, entraScope, stateKey: remote.stateKey, allowWrites: config.allowWrites, writeRole, trustProxy });

if (config.allowWrites && !config.writeEntities.length) {
  console.error(
    "fo-mcp: writes are enabled for every entity the F&O user may change. Set FO_WRITE_ENTITIES to the collections create_record and update_record may use."
  );
}
if (writeRole && !config.allowWrites) console.error(`fo-mcp: MCP_WRITE_ROLE=${writeRole} has no effect while FO_ALLOW_WRITES is off.`);

const tenantAuthority = `${config.authority}/${config.tenantId}`;

// ---------------------------------------------------------------- Token validation

// Entra is reached through the same dispatcher as the token requests, so HTTPS_PROXY applies to the key set too. A
// redirect is never followed: the keys that sign the tokens must come from the configured authority itself.
const jwks = createRemoteJWKSet(new URL(`${tenantAuthority}/discovery/v2.0/keys`), {
  [customFetch]: (url, options) =>
    fetch(url, { ...options, headers: Object.fromEntries(options.headers), dispatcher: shared.loginDispatcher, redirect: "manual" }) as unknown as Promise<globalThis.Response>,
});

/** Accept tokens from the v2 endpoint and, in case the app is set to v1 tokens, from the v1 issuer too. */
const issuers = [`${tenantAuthority}/v2.0`, `https://sts.windows.net/${config.tenantId}/`];

async function verifyAccessToken(token: string): Promise<AuthInfo> {
  // Tokens issued by our own OAuth front first, then tokens that come straight from Entra (scripts, advanced clients).
  const own = oauth.verifyProxyToken(token);
  if (own) return own;
  // The messages below end up in a quoted WWW-Authenticate parameter, so they must not carry quotes or backslashes of their own.
  if (!allowedClientApps.length) throw new InvalidTokenError("Unknown token. Sign in through your MCP client.");
  let payload: JWTPayload;
  try {
    ({ payload } = await jwtVerify(token, jwks, { issuer: issuers, audience: [audience, config.clientId], clockTolerance: CLOCK_TOLERANCE_S }));
  } catch (error) {
    // InvalidTokenError makes the middleware answer 401 with the resource metadata, so the client knows how to sign in.
    throw new InvalidTokenError(`Token rejected: ${(error as Error).message.replace(/["\\]/g, "'")}`);
  }
  const claims = payload as JWTPayload & {
    azp?: string; appid?: string; tid?: string; scp?: string; oid?: string; roles?: unknown; name?: string;
    preferred_username?: string; upn?: string; email?: string; unique_name?: string;
  };
  if (typeof claims.tid !== "string" || claims.tid.toLowerCase() !== config.tenantId.toLowerCase()) throw new InvalidTokenError("Token is not from this tenant");
  // Only delegated tokens of a signed in user. An app-only token for the same audience has no scp and no user to act for.
  if (!(claims.scp ?? "").split(" ").includes(scopeName)) throw new InvalidTokenError(`Token has no ${scopeName} scope of a signed in user`);
  // Any app in the tenant can ask Entra for a token to this API. Only the apps on the list may use one here directly.
  const app = claims.azp ?? claims.appid;
  if (typeof app !== "string" || !allowedClientApps.includes(app.toLowerCase())) {
    throw new InvalidTokenError("Tokens of this client app are not accepted here. Sign in through your MCP client or add the app to MCP_ALLOWED_CLIENT_APPS.");
  }
  // Sessions, caches and the audit log key on the object ID, so a token without one is refused rather than guessed at.
  if (typeof claims.oid !== "string" || !claims.oid) throw new InvalidTokenError("Token has no oid claim, so the user cannot be identified");
  return {
    token,
    clientId: app,
    scopes: (claims.scp ?? "").split(" ").filter(Boolean),
    expiresAt: claims.exp,
    resource: publicUrl,
    extra: {
      oid: claims.oid,
      name: claims.name,
      user: claims.preferred_username ?? claims.upn ?? claims.email ?? claims.unique_name,
      roles: Array.isArray(claims.roles) ? claims.roles.filter((r): r is string => typeof r === "string") : [],
    },
  };
}

/** Whether the user behind a request gets the write tools: writes are on and, with MCP_WRITE_ROLE, the user has that app role. */
function mayWrite(auth: AuthInfo | undefined): boolean {
  if (!config.allowWrites) return false;
  if (!writeRole) return true;
  const roles = auth?.extra?.roles;
  return Array.isArray(roles) && roles.includes(writeRole);
}

// ---------------------------------------------------------------- One F&O client per user token

const clients = new Map<string, { client: FoClient; expiresAt: number }>();

/** The F&O client for the user behind a request. Keyed by the token, so a refreshed token gets a fresh on-behalf-of exchange. */
function clientFor(auth: AuthInfo | undefined): FoClient {
  if (!auth) throw new FoError("No signed in user on this request.");
  const key = createHash("sha256").update(auth.token).digest("hex");
  const now = Date.now();
  for (const [k, v] of clients) if (v.expiresAt < now) clients.delete(k);
  let entry = clients.get(key);
  if (!entry) {
    const user = (auth.extra?.user as string | undefined) ?? (auth.extra?.name as string | undefined);
    const client = new FoClient(shared, onBehalfOfTokenSource(shared, auth.token), user, userKey(auth));
    entry = { client, expiresAt: (auth.expiresAt ?? now / 1000 + 3600) * 1000 };
    clients.set(key, entry);
  }
  return entry.client;
}

/** A stable ID of the signed in user: the Entra object ID, which stays the same across token refreshes. */
function userKey(auth: AuthInfo | undefined): string | undefined {
  return (auth?.extra?.oid as string | undefined) ?? (auth?.extra?.user as string | undefined);
}

// ---------------------------------------------------------------- MCP sessions

/** An MCP session belongs to the user who opened it and ends after an hour without requests. */
interface McpSession {
  transport: StreamableHTTPServerTransport;
  user: string | undefined;
  usedAt: number;
  /** Whether the session offers the write tools, decided by the user's roles when it started. */
  writes: boolean;
  /** POST requests the transport is answering now. The GET stream of a session never ends on its own and does not count. */
  inFlight: number;
  /** Set by endSession: the transport closes once the last request in flight is answered. */
  ending: boolean;
}

const SESSION_IDLE_MS = 60 * 60_000;
/** A session holds about 100 KB. Past these limits the least recently used session is closed. */
const MAX_SESSIONS_PER_USER = 10;
const MAX_SESSIONS = 500;
const sessions = new Map<string, McpSession>();

/** How long a create or update already sent to F&O may wait for its answer after SIGTERM, within the 25 s before the process exits. */
const WRITE_GRACE_MS = 20_000;

/**
 * End a session: take it out of the map, so no further request reaches it. Its transport closes once the requests
 * it is answering are out. Closing the transport aborts every tool call still running in it. A create or update
 * already sent to F&O would be cut off with its answer, the one that says whether F&O applied it, never reaching the
 * client. Like the SIGTERM path, a session close lets a sent write get its answer first.
 */
function endSession(id: string, session: McpSession): void {
  sessions.delete(id);
  session.ending = true;
  if (session.inFlight === 0) void session.transport.close().catch(() => {});
}

/** Hand a POST to the session's transport and count it until its answer is out, so endSession can wait for it. */
function handleInSession(session: McpSession, req: Request, res: Response): Promise<void> {
  session.inFlight++;
  res.on("close", () => {
    session.inFlight--;
    if (session.ending && session.inFlight === 0) void session.transport.close().catch(() => {});
  });
  return session.transport.handleRequest(req, res, req.body);
}

/** End the least recently used session among those that match, to make room for a new one. */
function closeOldest(match: (s: McpSession) => boolean): void {
  let oldest: [string, McpSession] | undefined;
  for (const entry of sessions) if (match(entry[1]) && (!oldest || entry[1].usedAt < oldest[1].usedAt)) oldest = entry;
  if (oldest) endSession(oldest[0], oldest[1]);
}

/** End sessions nobody used for an hour. Clients that lose the connection never send DELETE. */
function sweepSessions(): void {
  const now = Date.now();
  for (const [id, s] of sessions) if (now - s.usedAt > SESSION_IDLE_MS) endSession(id, s);
}

/** The session of this request, only when the same user opened it. Anything else counts as unknown. */
function sessionFor(req: Request, res: Response): McpSession | undefined {
  const id = req.headers["mcp-session-id"];
  const session = typeof id === "string" ? sessions.get(id) : undefined;
  if (!session || session.user !== userKey(req.auth)) return undefined;
  res.locals.mcpSession = id; // for the request line, see the log middleware
  if (session.writes !== mayWrite(req.auth)) {
    // The user's write role changed since the session started, it is gone or it came with a new token. The tools of a
    // session are fixed when it starts, so ending it makes the client start one with or without the write tools. The
    // request that brings the change is answered 404 before anything of it runs.
    endSession(id as string, session);
    return undefined;
  }
  session.usedAt = Date.now();
  return session;
}

/** What the MCP spec asks for when a session ID is unknown or expired: 404, so the client starts a new session. */
function unknownSession(res: Response): void {
  res.status(404).json({ jsonrpc: "2.0", error: { code: -32001, message: "Session not found. Start a new session with an initialize request." }, id: null });
}

/** Requests to the MCP endpoint per signed in user and minute. Per user, not per address: many users share an office address. */
const mcpLimiter = new RateLimiter(600);

function limitPerUser(req: Request, res: Response, next: NextFunction): void {
  const wait = mcpLimiter.hit(userKey(req.auth) ?? "-");
  if (wait === undefined) return next();
  res.set("Retry-After", String(wait));
  res.status(429).json({ jsonrpc: "2.0", error: { code: -32000, message: `Too many requests for this user, try again in ${wait} s.` }, id: null });
}

// ---------------------------------------------------------------- HTTP

async function main(): Promise<void> {
  // Check once that Entra answers for this tenant, so a wrong FO_TENANT_ID fails at start and not at the first sign in.
  const discoveryUrl = `${tenantAuthority}/v2.0/.well-known/openid-configuration`;
  const discovery = await fetch(discoveryUrl, { dispatcher: shared.loginDispatcher, redirect: "manual", signal: AbortSignal.timeout(config.timeoutMs) });
  await discovery.body?.cancel().catch(() => undefined);
  if (discovery.status >= 300 && discovery.status < 400) {
    throw new Error(`Entra answered the metadata request for tenant ${config.tenantId} with a redirect to ${redirectHost(discovery.headers.get("location"), discoveryUrl)}, which is not followed. Check FO_AUTHORITY.`);
  }
  if (!discovery.ok) throw new Error(`Cannot read Entra metadata for tenant ${config.tenantId}: ${discovery.status}`);

  const app = express();
  app.disable("x-powered-by");
  // Only the exact path of MCP_PUBLIC_URL is the MCP endpoint. By default Express would serve it at /mcp/ and /MCP as
  // well, while what counts as a request in flight, where CORS applies and the format of an error below all compare
  // req.path with that path and would miss those variants. The well-known routes are mounted as prefixes and stay as
  // they are. Set before the first route, the router takes the settings when it is made.
  app.set("strict routing", true);
  app.set("case sensitive routing", true);
  // A browser that saw the server over https keeps to https for a year, so a later visit cannot be sent over plain http.
  // Not on localhost: the policy belongs to the host name and not to the port, so it would move every http://localhost
  // port to https for a year, the callback Claude Code signs in with included.
  if (publicUrl.protocol === "https:" && !remote.loopback && publicUrl.hostname !== "[::1]") {
    app.use((_req, res, next) => {
      res.set("Strict-Transport-Security", "max-age=31536000");
      next();
    });
  }
  /** Requests being answered, so a shutdown can let them finish. The GET SSE stream of a session never finishes on its own and does not count. */
  let inFlight = 0;
  let stopping = false;
  // One line per request, before anything can reject it. The path only: query strings carry codes and state.
  app.use((req, res, next) => {
    if (!(req.method === "GET" && req.path === publicUrl.pathname)) {
      inFlight++;
      res.on("close", () => {
        inFlight--;
        if (stopping && inFlight === 0) process.exit(0);
      });
    }
    const started = Date.now();
    const client = clientIp(req, trustProxy);
    res.on("finish", () => {
      // The MCP session is the one key the audit lines share with these, so a tool call can be tied to the address it
      // came from. An initialize gets its ID in the answer, a later request names a session the server accepted for
      // this user. The ID a client merely sent is not printed: anyone can put any text there, also on a refused request.
      const session = res.getHeader("mcp-session-id") ?? res.locals.mcpSession ?? "-";
      // The path and the user agent are the caller's text. Node passes tabs and bytes over 0x7f in a header, so both are
      // made one line here, and the user agent is cut, or a caller could draw a second entry into this one.
      const agent = oneLine(req.headers["user-agent"] ?? "-", 200);
      console.error(`${req.method} ${oneLine(req.path, 200)} ${res.statusCode} ${Date.now() - started} ms ${client} ${session} ${agent}`);
    });
    next();
  });
  // Before the Host check: a liveness or readiness probe sends the replica's own address as Host.
  app.get("/health", (_req, res) => {
    // /health answers anyone, so it tells nothing about the environment, the users or the load.
    res.json({ status: "ok", name: "fo-mcp", version });
  });
  app.use(hostHeaderValidation(allowedHosts));
  app.use(express.json({ limit: `${BODY_LIMIT_KB}kb` }));
  // Browser based clients call the MCP endpoint, the metadata and the token endpoints from their own origin. The pages a
  // person sees (/authorize, the consent form, /callback) get no CORS headers, no other site has any business reading them.
  const corsAll = cors({ origin: "*", exposedHeaders: ["Mcp-Session-Id", "WWW-Authenticate"] });
  const corsPaths = new Set([publicUrl.pathname, "/token", "/register", "/revoke"]);
  app.use((req, res, next) => (corsPaths.has(req.path) || req.path.startsWith("/.well-known/") ? corsAll(req, res, next) : next()));
  // Protected resource metadata points clients at our own OAuth front, which signs users in with Entra behind it.
  // The SDK serves it at the path specific URL (/.well-known/oauth-protected-resource/mcp), clients that
  // only know the older root URL get the same document there.
  // With FO_NAME set the resource name carries the environment, so a client that shows it tells a TEST connector from
  // a PROD one. Without it the name stays bare: this document answers anyone, and the default of the name is the F&O
  // host, which the consent page withholds from strangers on purpose.
  const resourceName = process.env.FO_NAME?.trim() ? `fo-mcp ${config.name}` : "fo-mcp";
  const resourceMetadata = { resource: publicUrl.href, authorization_servers: [oauth.metadata.issuer], scopes_supported: [scope], resource_name: resourceName };
  app.use(mcpAuthMetadataRouter({ oauthMetadata: oauth.metadata, resourceServerUrl: publicUrl, scopesSupported: [scope], resourceName }));
  app.get("/.well-known/oauth-protected-resource", (_req, res) => {
    res.json(resourceMetadata);
  });
  app.use(oauth.router);
  // Something at the root for people who open the host in a browser, unless the MCP endpoint itself is the root.
  if (publicUrl.pathname !== "/") {
    app.get("/", (_req, res) => {
      res.json({ name: "fo-mcp", version, mcp: publicUrl.href });
    });
  }

  const auth = requireBearerAuth({ verifier: { verifyAccessToken }, resourceMetadataUrl: getOAuthProtectedResourceMetadataUrl(publicUrl) });

  app.post(publicUrl.pathname, auth, limitPerUser, async (req: Request, res: Response) => {
    sweepSessions();
    if (req.headers["mcp-session-id"] !== undefined) {
      const session = sessionFor(req, res);
      if (!session) return unknownSession(res);
      await handleInSession(session, req, res);
      return;
    }
    if (!isInitializeRequest(req.body)) {
      res.status(400).json({ jsonrpc: "2.0", error: { code: -32000, message: "No session. Send an initialize request first." }, id: null });
      return;
    }
    const user = userKey(req.auth);
    const writes = mayWrite(req.auth);
    while ([...sessions.values()].filter((s) => s.user === user).length >= MAX_SESSIONS_PER_USER) closeOldest((s) => s.user === user);
    while (sessions.size >= MAX_SESSIONS) closeOldest(() => true);
    const transport: StreamableHTTPServerTransport = new StreamableHTTPServerTransport({
      sessionIdGenerator: () => randomUUID(),
      onsessioninitialized: (id) => {
        sessions.set(id, { transport, user, usedAt: Date.now(), writes, inFlight: 0, ending: false });
      },
    });
    transport.onclose = () => {
      if (transport.sessionId) sessions.delete(transport.sessionId);
    };
    const server = createFoServer({
      version, shared, resolve: (extra) => clientFor(extra.authInfo), allowWrites: writes, missingWriteRole: config.allowWrites && !writes ? writeRole : undefined,
    });
    await server.connect(transport);
    await transport.handleRequest(req, res, req.body);
  });

  const existing = async (req: Request, res: Response) => {
    const session = sessionFor(req, res);
    if (!session) return unknownSession(res);
    await session.transport.handleRequest(req, res);
  };
  app.get(publicUrl.pathname, auth, limitPerUser, existing);
  app.delete(publicUrl.pathname, auth, limitPerUser, existing);

  // Errors that reach Express, mostly bodies that are not valid JSON or form data. Answer in the format of the endpoint and
  // never log the error text, a parse error quotes part of the body, which can be a token.
  app.use((error: Error & { status?: number; type?: string }, req: Request, res: Response, _next: express.NextFunction) => {
    const status = error.status && error.status >= 400 && error.status < 500 ? error.status : 500;
    console.error(`${req.method} ${oneLine(req.path, 200)} failed: ${error.type ?? error.name} ${status}`);
    if (res.headersSent) return;
    // A body over the limit is mostly a write with a very long text. Answered as an internal error, the model would send
    // the same call again.
    const tooLarge = `The request is over the ${BODY_LIMIT_KB} KB this server accepts in one call. Shorten the long text values in it.`;
    if (req.path === publicUrl.pathname) {
      const rpc =
        status === 400 ? { code: -32700, message: "Parse error" } : status === 413 ? { code: -32600, message: tooLarge } : { code: -32603, message: "Internal error" };
      res.status(status).json({ jsonrpc: "2.0", error: rpc, id: null });
    } else {
      const description = status === 400 ? "The request body could not be read" : status === 413 ? tooLarge : "Request failed";
      res.status(status).json({ error: status === 500 ? "server_error" : "invalid_request", error_description: description });
    }
  });

  const server = await new Promise<ReturnType<typeof app.listen>>((resolve, reject) => {
    const listening = app.listen(port, host, (error?: Error) => (error ? reject(error) : resolve(listening)));
    listening.on("error", reject);
  });
  // See KEEP_ALIVE_MS. Node asks for the headers timeout to stay above the keep-alive timeout, or a connection could be
  // closed while a request's headers are still arriving on it.
  server.keepAliveTimeout = KEEP_ALIVE_MS;
  server.headersTimeout = KEEP_ALIVE_MS + 5_000;
  const writes = !config.allowWrites ? "read-only" : writeRole ? `writes for users with the ${writeRole} role` : "writes enabled";
  const addresses = trustProxy ? `client addresses from X-Forwarded-For behind ${trustProxy} ${trustProxy === 1 ? "proxy" : "proxies"}` : "client addresses from the connection";
  console.error(
    `fo-mcp ${version} listening on ${host}:${port}, public URL ${publicUrl}, F&O ${config.url}, users sign in with ${scope}, ${writes}, ${remote.directTokens}, ${addresses}`
  );
  // As PID 1 in a container Node ignores SIGTERM and SIGINT unless it handles them. On a signal take no new connections
  // and stop the tool calls in flight: they answer at once that the server is restarting, and each still writes its
  // audit line. A tool call may take longer than the replica has left, so waiting for F&O is no option in general. A
  // create or update already sent is the exception: it gets WRITE_GRACE_MS for F&O's answer, so the user learns whether
  // it was applied, and is stopped after that with the note that F&O may have applied it. Then exit once those answers
  // are out. Open SSE streams end with the process. The fallback covers a sign in waiting on Entra and stays below the
  // 30 s Container Apps gives a replica before it kills it.
  const stop = () => {
    if (stopping) return;
    stopping = true;
    shared.shutdown(WRITE_GRACE_MS);
    server.close();
    if (inFlight === 0) process.exit(0);
    setTimeout(() => process.exit(0), 25_000).unref();
  };
  for (const signal of ["SIGTERM", "SIGINT"] as const) process.on(signal, stop);
  // A stray rejection must not end the process: every user's sign in and session lives in its memory. Log it instead.
  process.on("unhandledRejection", (reason) => {
    console.error(`fo-mcp: unhandled rejection: ${reason instanceof Error ? reason.message : String(reason)}`);
  });
}

main().catch((error: unknown) => {
  console.error(`fo-mcp: ${(error as Error).message}`);
  process.exit(1);
});
