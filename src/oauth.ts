// OAuth front for the remote server.
//
// MCP clients expect an authorization server with dynamic client registration, PKCE metadata and a
// resource parameter they choose. Entra offers none of that, so this module makes the MCP server its own
// authorization server from the client's point of view and uses Entra behind it:
//
//   client  --register--->  /register   (a signed client id, nothing is stored)
//   client  --authorize-->  /authorize  --consent page-->  /consent  --redirect-->  Entra sign in  --code-->  /callback
//   client  --code------->  /token      (PKCE checked here, Entra tokens stay on the server)
//   client  --Bearer----->  /mcp        (opaque token, mapped to the user's Entra token for on-behalf-of)
//
// Entra tokens never reach the client and client tokens never reach F&O, which is what the MCP
// authorization specification asks for. The consent page makes every new client visible to the user before
// Entra signs them in silently. A client the browser approved before skips the page, and Entra then shows its
// account picker instead, so no sign in goes through without the user seeing one. A cookie binds each sign in
// to the browser that started it.
//
// A sign in in progress is kept nowhere on the server. /authorize seals the request into the consent form, and the
// browser leaves for Entra with it sealed into the state, so a flood of /authorize requests costs no memory and a
// sign in started before a restart still finishes after it. Only a state Entra has answered is remembered, to refuse
// it a second time.
import { InvalidTokenError } from "@modelcontextprotocol/sdk/server/auth/errors.js";
import type { AuthInfo } from "@modelcontextprotocol/sdk/server/auth/types.js";
import type { OAuthMetadata } from "@modelcontextprotocol/sdk/shared/auth.js";
import { createCipheriv, createDecipheriv, createHash, createHmac, hkdfSync, randomBytes, timingSafeEqual } from "node:crypto";
import type { IncomingMessage } from "node:http";
import { isIP } from "node:net";
import express, { type CookieOptions, type NextFunction, type Request, type Response, type Router } from "express";
import { fetch } from "undici";
import type { FoShared } from "./fo.js";

export interface OAuthProxyOptions {
  /** Configuration and the dispatcher for Entra, which honours HTTPS_PROXY like the rest of the server. */
  shared: FoShared;
  /** Public origin of the MCP server, for example https://mcp.example.com */
  origin: string;
  /** Scope clients ask for, shown to users at sign in. */
  scope: string;
  /** The scope requested from Entra for the user token, in the GUID form Entra accepts for an app calling itself. */
  entraScope: string;
  /** Key for client ids, consent cookies, CSRF tokens and sealed sign ins (MCP_STATE_KEY). Without it one is derived from the client secret. */
  stateKey?: string;
  /** Whether the server offers the write tools, for the consent page. */
  allowWrites: boolean;
  /** The app role a user needs for the write tools (MCP_WRITE_ROLE), for the consent page. */
  writeRole?: string;
  /** Proxies in front that append to X-Forwarded-For (MCP_TRUST_PROXY), for the limits per address. See clientIp. */
  trustProxy: number;
}

/** What a client id carries: the registration itself, signed, so nothing has to be stored and it survives a restart. */
interface Registration {
  name?: string;
  redirectUris: string[];
}

/** An authorize request the user has not approved yet. The consent form carries it sealed, see sealRequest. */
interface SignInRequest {
  clientId: string;
  redirectUri: string;
  /** The client's own state, handed back to it unchanged. */
  state?: string;
  codeChallenge: string;
  createdAt: number;
}

/** A sign in on its way through Entra. The state sent to Entra carries it sealed, see sealEntraState. */
interface EntraSignIn {
  /** SHA-256 of the client id. The id itself can be 1,500 characters and only has to be matched at /token. */
  clientHash: string;
  redirectUri: string;
  state?: string;
  codeChallenge: string;
  /** The PKCE verifier of the server's own exchange with Entra. */
  verifier: string;
  /** Hash of the cookie that binds the sign in to the browser that left for Entra. */
  binding: string;
  /** When the browser left for Entra. */
  createdAt: number;
}

interface EntraTokens {
  accessToken: string;
  refreshToken?: string;
  expiresAt: number;
  oid?: string;
  user?: string;
  name?: string;
  /** App roles of the user in the server's own app registration, from the roles claim. */
  roles: string[];
}

interface IssuedCode extends EntraTokens {
  /** SHA-256 of the client id the code was issued to, from the sealed state. */
  clientHash: string;
  redirectUri: string;
  codeChallenge: string;
  createdAt: number;
}

/** A code that was exchanged already, kept until it would have expired to recognise a replay. */
interface UsedCode {
  until: number;
  /** The sign in the exchange started, revoked when the code comes back. */
  family?: string;
}

interface Session extends EntraTokens {
  clientId: string;
  scope: string;
  refresh: string;
  /** Until when the refresh token works. Separate from expiresAt, so a client can refresh after its access token expired. */
  refreshExpiresAt: number;
  /**
   * One sign in and every pair refreshed from it. A refresh token used twice revokes the whole family. Every refresh
   * token starts with the family it belongs to, see exchangedIn.
   */
  family: string;
  /** The refresh token this pair replaced. It stays in `retired` as long as this pair lives. */
  replaced?: string;
}

type TokenAnswer = { status: number; body: Record<string, unknown> };

/**
 * The latest exchanged refresh token of a sign in with the answer it got, so a parallel request that just missed the
 * exchange gets the same pair. Recognising a replay needs no entry here, see exchangedIn. An entry leaves with the
 * pair it was exchanged for, see Session.replaced, so it is there for the whole grace however old the sign in was.
 */
interface Retired {
  family: string;
  clientId: string;
  retiredAt: number;
  answer: TokenAnswer;
}

/** A failed call to the Entra token endpoint. `grantError` is true when Entra refused the grant itself, not when it was unreachable. */
class EntraError extends Error {
  constructor(message: string, readonly grantError: boolean) {
    super(message);
  }
}

const CODE_TTL_MS = 5 * 60_000;
/** How long a user may take at the consent page, and again at the Entra sign in. */
const SIGN_IN_TTL_MS = 10 * 60_000;
const SESSION_TTL_MS = 8 * 60 * 60_000;
/** A refresh token works for this long after it was issued. Every refresh issues a new one. */
const REFRESH_TTL_MS = SESSION_TTL_MS;
/** No genuine authorize request comes near this length. */
const MAX_AUTHORIZE_URL = 4096;
/**
 * The longest client state carried through Entra, in bytes of its JSON form. Claude and the MCP SDK send under 100.
 * With the largest client id and redirect URI the Entra URL then stays under 4,096 characters, which every browser,
 * proxy and Entra itself accept.
 */
const MAX_STATE = 1024;
/** A refresh token presented again this soon after its exchange is a parallel request that just missed it, not a replay. */
const REUSE_GRACE_MS = 5000;
/** The longest value accepted in a query or form field. Entra codes for personal Microsoft accounts run past 2,000 characters. */
const MAX_FIELD = 8192;
/** A client id carries its redirect URIs, so it is kept short enough for the authorize URL to stay under MAX_AUTHORIZE_URL. */
const MAX_CLIENT_ID = 1500;
/** How long a browser remembers an approval, and for how many clients. */
const CONSENT_TTL_MS = 30 * 24 * 60 * 60_000;
const MAX_CONSENTS = 20;
/**
 * A sign in holds the user's Entra tokens, about 4 KB, for up to 8 hours whether /mcp is ever called or not. Past these
 * limits the sign in refreshed least recently ends, the user's own first, so one account cannot fill the memory.
 */
const MAX_SIGN_INS_PER_USER = 20;
const MAX_SIGN_INS = 5000;
/** The scopes a client may ask for besides the configured one. They are accepted and ignored, the issued scope is the configured one. */
const OIDC_SCOPES = ["openid", "profile", "offline_access", "email"];
const LOOPBACK_HOSTS = ["localhost", "127.0.0.1", "[::1]"];

/** Headers of every page the server shows in a browser: nothing loads from elsewhere, nothing frames it, nothing is cached. */
const PAGE_HEADERS = {
  "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'",
  "X-Frame-Options": "DENY",
  "Cache-Control": "no-store",
  "Referrer-Policy": "no-referrer",
  "X-Content-Type-Options": "nosniff",
};

/** Headers of the redirects that carry codes and state. */
const REDIRECT_HEADERS = { "Cache-Control": "no-store", "Referrer-Policy": "no-referrer" };

function random(): string {
  return randomBytes(32).toString("base64url");
}

function s256(value: string): string {
  return createHash("sha256").update(value).digest("base64url");
}

/** Compare two strings in constant time, so a signature cannot be guessed one character at a time. */
function same(a: string, b: string): boolean {
  const x = Buffer.from(a);
  const y = Buffer.from(b);
  return x.length === y.length && timingSafeEqual(x, y);
}

/** A request field as a string of sane length, undefined for a missing value, an array or an object. */
function field(source: unknown, name: string): string | undefined {
  const value = (source as Record<string, unknown> | undefined)?.[name];
  return typeof value === "string" && value.length <= MAX_FIELD ? value : undefined;
}

/**
 * The address of the client, for the limits per address and the request log. Every proxy in front appends the address
 * it got the request from to X-Forwarded-For, so behind `trustedHops` of them (MCP_TRUST_PROXY, 1 for the Container
 * Apps ingress) the client is that many entries from the end. Entries further left come from the client and can be
 * anything. With 0, or without the header, it is the address of the connection.
 */
export function clientIp(req: IncomingMessage, trustedHops = 1): string {
  const forwarded = req.headers["x-forwarded-for"];
  const hops = trustedHops > 0 && typeof forwarded === "string" ? forwarded.split(",").map((h) => h.trim()).filter(Boolean) : [];
  const direct = req.socket.remoteAddress ?? "-";
  const address = hops.length ? hops[Math.max(0, hops.length - trustedHops)] : direct;
  // Some proxies append address:port, which would give every connection a limit of its own.
  const v4 = /^(\d{1,3}(?:\.\d{1,3}){3}):\d+$/.exec(address);
  const v6 = /^\[([0-9A-Fa-f:.]+)\](?::\d+)?$/.exec(address);
  const found = v4?.[1] ?? v6?.[1] ?? address;
  // Only an address counts. With MCP_TRUST_PROXY higher than the proxies really in front, the counted hop is whatever
  // the client sent, and its text would go into the request line as it is, spaces and a made up session included.
  return isIP(found) ? found : direct;
}

/**
 * Fixed window counters per key, for the abuse limits. Windows start in the order their keys are added, so the
 * oldest window is always first in the map, which keeps pruning cheap and the memory bounded.
 */
export class RateLimiter {
  private readonly windows = new Map<string, { start: number; count: number }>();

  constructor(
    private readonly limit: number,
    private readonly windowMs = 60_000,
    private readonly maxKeys = 10_000
  ) {}

  /** Count one request of `key`. Returns undefined when it may go ahead, otherwise the seconds until it may try again. */
  hit(key: string, now = Date.now()): number | undefined {
    let window = this.windows.get(key);
    if (!window || now - window.start >= this.windowMs) {
      this.windows.delete(key);
      for (const [k, w] of this.windows) {
        // Expired windows go, and when every key is active the oldest goes too, so the map never grows past maxKeys.
        if (now - w.start < this.windowMs && this.windows.size < this.maxKeys) break;
        this.windows.delete(k);
      }
      window = { start: now, count: 0 };
      this.windows.set(key, window);
    }
    window.count++;
    return window.count > this.limit ? Math.max(1, Math.ceil((window.start + this.windowMs - now) / 1000)) : undefined;
  }
}

/** Redirect URIs we accept: local MCP clients and the Claude apps. */
function redirectAllowed(uri: string): boolean {
  try {
    const u = new URL(uri);
    // A fragment would swallow the parameters we append, user info only serves to disguise the host.
    if (u.hash || u.username || u.password) return false;
    if (LOOPBACK_HOSTS.includes(u.hostname) && (u.protocol === "http:" || u.protocol === "https:")) return true;
    return ["https://claude.ai/api/mcp/auth_callback", "https://claude.com/api/mcp/auth_callback"].includes(uri);
  } catch {
    return false;
  }
}

/**
 * Whether a redirect URI is one the client registered. Exact match, except that a loopback redirect may use any
 * port (RFC 8252 section 7.3): native clients pick a free port when they start listening for the answer.
 */
function redirectRegistered(registered: string[], uri: string): boolean {
  if (registered.includes(uri)) return true;
  const parse = (value: string) => {
    try {
      return new URL(value);
    } catch {
      return undefined;
    }
  };
  const u = parse(uri);
  if (!u || !LOOPBACK_HOSTS.includes(u.hostname)) return false;
  return registered.some((r) => {
    const g = parse(r);
    return !!g && g.protocol === u.protocol && g.hostname === u.hostname && g.pathname === u.pathname && g.search === u.search;
  });
}

/** A client name fit for the consent page: at most 100 characters, none of them control or format characters. */
function validClientName(name: string): boolean {
  return /^[^\p{C}\p{Zl}\p{Zp}]{1,100}$/u.test(name);
}

function decodeUser(accessToken: string): Pick<EntraTokens, "oid" | "user" | "name" | "roles"> {
  try {
    const payload = JSON.parse(Buffer.from(accessToken.split(".")[1], "base64url").toString("utf8")) as Record<string, unknown>;
    const text = (value: unknown) => (typeof value === "string" && value ? value : undefined);
    const roles = Array.isArray(payload.roles) ? payload.roles.filter((r): r is string => typeof r === "string") : [];
    // A personal Microsoft account carries only email and unique_name (live.com#<email>) in a v1 token.
    const user = text(payload.preferred_username) ?? text(payload.upn) ?? text(payload.email) ?? text(payload.unique_name);
    return { oid: text(payload.oid), user, name: text(payload.name), roles };
  } catch {
    return { roles: [] };
  }
}

/**
 * Entra error text without the Trace ID, Correlation ID and Timestamp lines. They mean nothing to the client and only
 * identify the request, the full text goes to the server log for the administrator.
 */
function entraMessage(text: string): string {
  return text.split(/\s*(?:Trace ID|Correlation ID|Timestamp):/)[0].trim();
}

/** One line for the server log: no line breaks a reader of the log could mistake for another entry, and a sane length. */
export function oneLine(text: string, max = 2000): string {
  // The C1 controls and the Unicode line separators as well: some log readers break a line at them, and a terminal
  // may act on them.
  return text.replace(/[\u0000-\u001f\u007f-\u009f\u2028\u2029]+/g, " ").slice(0, max);
}

function escapeHtml(text: string): string {
  return text.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!);
}

/** Show a small HTML page. `body` is trusted markup, every value from a request in it must go through escapeHtml. */
function page(res: Response, status: number, title: string, body: string, headers: Record<string, string> = {}): void {
  res.status(status).set({ ...PAGE_HEADERS, ...headers }).type("html").send(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>${escapeHtml(title)}</title>
<style>body{font:16px/1.5 system-ui,sans-serif;max-width:34rem;margin:3rem auto;padding:0 1rem;color:#1b1b1b}h1{font-size:1.3rem}
dt{font-weight:600;margin-top:.6rem}dd{margin:0}code{word-break:break-all}button{font:inherit;padding:.4rem 1.2rem;margin:1rem .5rem 0 0}
.note{color:#555;font-size:.9rem}a{color:inherit}@media(prefers-color-scheme:dark){body{background:#1b1b1b;color:#eee}.note{color:#aaa}}</style></head>
<body>${body}</body></html>`);
}

/**
 * The cookies of a request by name. A name that comes twice counts as missing: the second one was set somewhere else on
 * the same site, by another host for the parent domain for example, and which of the two is ours is unknown.
 */
function cookies(req: Request): Map<string, string> {
  const jar = new Map<string, string>();
  const twice = new Set<string>();
  for (const part of (req.headers.cookie ?? "").split(";")) {
    const eq = part.indexOf("=");
    if (eq <= 0) continue;
    const name = part.slice(0, eq).trim();
    if (jar.has(name)) twice.add(name);
    jar.set(name, part.slice(eq + 1).trim());
  }
  for (const name of twice) jar.delete(name);
  return jar;
}

/** The host a redirect points to, for messages. Never the whole URL, its query can carry anything. */
export function redirectHost(location: string | null, base: string): string {
  try {
    return new URL(location ?? "", base).host;
  } catch {
    return "an unreadable address";
  }
}

export function createOAuthProxy({ shared, origin, scope, entraScope, stateKey, allowWrites, writeRole, trustProxy }: OAuthProxyOptions) {
  const { config } = shared;
  const tenantAuthority = `${config.authority}/${config.tenantId}`;
  const secure = origin.startsWith("https:");
  // Without MCP_STATE_KEY the key comes from the client secret, so registrations survive a restart without extra
  // configuration. Rotating the secret then ends them, and clients register again.
  const key = stateKey ? Buffer.from(stateKey, "utf8") : Buffer.from(hkdfSync("sha256", config.clientSecret, "fo-mcp", "fo-mcp state key v1", 32));
  /** Sign a value for one purpose. The purpose keeps a client id from passing as a consent cookie or a CSRF token. */
  const sign = (purpose: string, value: string) => createHmac("sha256", key).update(`${purpose}\n${value}`).digest("base64url");
  /** The key that seals sign ins in progress, kept apart from the signing key by its own HKDF label. */
  const sealKey = Buffer.from(hkdfSync("sha256", key, "fo-mcp", "fo-mcp sign in seal v1", 32));

  // On https the cookies carry the __Host- prefix: the browser then takes them only from this host, with Path=/ and
  // without Domain, so another app under the same parent domain (every *.azurecontainerapps.io app is one site) cannot
  // plant its own. On plain http, which only runs on localhost, the cookies are not Secure, and the prefix requires that.
  const prefix = secure ? "__Host-" : "";
  const consentCookie = `${prefix}fo_consent`;
  const csrfCookie = `${prefix}fo_csrf`;
  /** The name of the cookie that binds one sign in to its browser. Derived from the sign in, so parallel sign ins do not collide. */
  const bindingCookie = (binding: string) => `${prefix}fo_signin_${binding.slice(0, 16)}`;
  const cookieOptions = (maxAge?: number): CookieOptions => ({ httpOnly: true, sameSite: "lax", secure, path: "/", ...(maxAge ? { maxAge } : {}) });

  /** States Entra answered with a code that worked, by hash, until they would have expired. A replay of one is refused. */
  const usedStates = new Map<string, number>();
  const codes = new Map<string, IssuedCode>();
  const usedCodes = new Map<string, UsedCode>();
  const sessions = new Map<string, Session>();
  const refreshTokens = new Map<string, string>(); // refresh token -> access token
  const families = new Map<string, string>(); // family -> its current access token
  const retired = new Map<string, Retired>(); // the latest exchanged refresh token of a sign in -> what it was exchanged for
  /** Refreshes waiting for Entra, by refresh token. Parallel requests with the same token share one answer. */
  const refreshing = new Map<string, { clientId: string | undefined; answer: Promise<{ status: number; body: Record<string, unknown> }> }>();
  // claude.ai registers and trades tokens from shared addresses, so those limits are generous. The pages are for one person.
  const limits = {
    authorize: new RateLimiter(30),
    consent: new RateLimiter(30),
    callback: new RateLimiter(30),
    register: new RateLimiter(60),
    token: new RateLimiter(300),
    revoke: new RateLimiter(300),
  };

  function sweep(): void {
    const now = Date.now();
    for (const [k, until] of usedStates) if (until < now) usedStates.delete(k);
    for (const [k, v] of codes) if (now - v.createdAt > CODE_TTL_MS) codes.delete(k);
    for (const [k, v] of usedCodes) if (v.until < now) usedCodes.delete(k);
    for (const [k, v] of sessions) {
      if (v.expiresAt < now && v.refreshExpiresAt < now) {
        sessions.delete(k);
        refreshTokens.delete(v.refresh);
        if (v.replaced) retired.delete(v.replaced);
        if (families.get(v.family) === k) families.delete(v.family);
      }
    }
  }

  /** End a sign in: its current pair stops working and its refresh token cannot be used any more. */
  function revokeFamily(family: string): void {
    const access = families.get(family);
    const session = access ? sessions.get(access) : undefined;
    if (access) sessions.delete(access);
    if (session) refreshTokens.delete(session.refresh);
    if (session?.replaced) retired.delete(session.replaced);
    families.delete(family);
  }

  /**
   * Make room for a new sign in of a user. Sessions are added in the order their pairs were issued and a refresh adds
   * the new pair at the end, so the first entries are the sign ins refreshed least recently, and those end first.
   */
  function makeRoom(oid: string): void {
    let own = 0;
    for (const s of sessions.values()) if (s.oid === oid) own++;
    for (const s of sessions.values()) {
      if (own < MAX_SIGN_INS_PER_USER) break;
      if (s.oid !== oid) continue;
      revokeFamily(s.family);
      own--;
    }
    for (const s of sessions.values()) {
      if (sessions.size < MAX_SIGN_INS) break;
      revokeFamily(s.family);
    }
  }

  // ---------------------------------------------------------------- Client ids and cookies

  /** A client id that carries the registration and its signature, so /authorize and /token can check it without storage. */
  function clientIdFor(registration: Registration): { clientId: string; issuedAt: number } {
    const issuedAt = Math.floor(Date.now() / 1000);
    const body = { v: 1, ...(registration.name ? { n: registration.name } : {}), r: registration.redirectUris, t: issuedAt };
    const payload = Buffer.from(JSON.stringify(body)).toString("base64url");
    return { clientId: `dyn.${payload}.${sign("client", payload)}`, issuedAt };
  }

  /** The registration a client id carries, undefined for an id this server did not sign. */
  function readClient(clientId: string | undefined): Registration | undefined {
    const match = clientId && clientId.length <= MAX_CLIENT_ID ? /^dyn\.([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]{43})$/.exec(clientId) : null;
    if (!match || !same(match[2], sign("client", match[1]))) return undefined;
    try {
      const body = JSON.parse(Buffer.from(match[1], "base64url").toString("utf8")) as { v?: unknown; n?: unknown; r?: unknown };
      if (body.v !== 1 || !Array.isArray(body.r) || !body.r.every((u) => typeof u === "string")) return undefined;
      return { name: typeof body.n === "string" ? body.n : undefined, redirectUris: body.r as string[] };
    } catch {
      return undefined;
    }
  }

  /** A short handle of a client id for the consent cookie. Full ids carry their redirect URIs and would not fit 20 of them. */
  const handle = (clientId: string) => s256(clientId).slice(0, 22);

  /**
   * What an approval was given for besides the client: whether the page offered writes, to whom, and the F&O environment
   * the server reads. A remembered approval counts only while these stay the same, so a server that gains writes or is
   * pointed at another environment asks again. The page does not name the F&O host, since anyone who registers a client
   * can open it. The user still gets to approve again after such a change.
   */
  const consentScope = s256(JSON.stringify([allowWrites, allowWrites ? (writeRole ?? "") : "", new URL(config.url).host.toLowerCase()])).slice(0, 22);

  /** The handles of the clients this browser approved, from its signed consent cookie, for what the page shows now. */
  function approvedClients(req: Request): string[] {
    const value = cookies(req).get(consentCookie);
    const match = value ? /^([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]{43})$/.exec(value) : null;
    if (!match || !same(match[2], sign("consent", match[1]))) return [];
    try {
      const body = JSON.parse(Buffer.from(match[1], "base64url").toString("utf8")) as { e?: unknown; c?: unknown; s?: unknown };
      if (typeof body.e !== "number" || body.e * 1000 < Date.now() || !Array.isArray(body.c) || body.s !== consentScope) return [];
      return body.c.filter((c): c is string => typeof c === "string");
    } catch {
      return [];
    }
  }

  /** Remember in this browser that the user approved a client, the most recent MAX_CONSENTS of them. */
  function rememberConsent(req: Request, res: Response, clientId: string): void {
    const approved = [...approvedClients(req).filter((c) => c !== handle(clientId)), handle(clientId)].slice(-MAX_CONSENTS);
    const payload = Buffer.from(JSON.stringify({ e: Math.floor((Date.now() + CONSENT_TTL_MS) / 1000), s: consentScope, c: approved })).toString("base64url");
    res.cookie(consentCookie, `${payload}.${sign("consent", payload)}`, cookieOptions(CONSENT_TTL_MS));
  }

  /**
   * The CSRF token of a consent form. It is bound to a random cookie of this browser, so a form posted from another
   * browser does not pass. It does not stop another host of the same site: SameSite=Lax cookies go along with a form it
   * posts here, which is why /consent also checks where the post comes from (fromOwnPage). /authorize must see the
   * cookie to reuse it, also when the client opened it from another site, otherwise a second consent page in the same
   * browser would replace it and break the first one. That rules out SameSite=Strict.
   */
  function csrfToken(req: Request, res: Response, request: string): string {
    let browser = cookies(req).get(csrfCookie);
    if (!browser || !/^[A-Za-z0-9_-]{43}$/.test(browser)) browser = random();
    res.cookie(csrfCookie, browser, cookieOptions(SIGN_IN_TTL_MS));
    return sign("csrf", `${request}.${browser}`);
  }

  function csrfValid(req: Request, request: string, token: string | undefined): boolean {
    const browser = cookies(req).get(csrfCookie);
    return !!browser && !!token && same(token, sign("csrf", `${request}.${browser}`));
  }

  /**
   * Whether a form post comes from a page of this server, not from another host of the same site, which the cookies
   * alone cannot tell. Browsers send Origin with a POST. A browser that sends none, or "null" for a page with a strict
   * Referrer-Policy, still sends Sec-Fetch-Site, which must then say same-origin.
   */
  function fromOwnPage(req: Request): boolean {
    const from = req.headers.origin;
    if (from !== undefined && from !== "null") return from === origin;
    return req.headers["sec-fetch-site"] === "same-origin";
  }

  // ---------------------------------------------------------------- Sealed sign ins

  /**
   * Encrypt a sign in with AES-256-GCM, so the browser can carry it without reading or changing it. The purpose is
   * authenticated with it, so a consent request does not pass as an Entra state or the other way round.
   */
  function seal(purpose: string, value: object): string {
    const iv = randomBytes(12);
    const cipher = createCipheriv("aes-256-gcm", sealKey, iv);
    cipher.setAAD(Buffer.from(`fo-mcp ${purpose} v1`));
    const body = Buffer.concat([cipher.update(JSON.stringify(value), "utf8"), cipher.final()]);
    return Buffer.concat([iv, body, cipher.getAuthTag()]).toString("base64url");
  }

  /**
   * The value of a sealed sign in, undefined for anything this server did not seal for that purpose. Only the text seal
   * wrote is accepted: base64url decoding ignores a stray last character and unused low bits, and /callback remembers
   * used states by their text, so another spelling of the same bytes must not count as a new state.
   */
  function unseal<T>(purpose: string, text: string | undefined): T | undefined {
    if (!text || !/^[A-Za-z0-9_-]{40,}$/.test(text)) return undefined;
    const data = Buffer.from(text, "base64url");
    if (data.toString("base64url") !== text) return undefined;
    try {
      const decipher = createDecipheriv("aes-256-gcm", sealKey, data.subarray(0, 12));
      decipher.setAAD(Buffer.from(`fo-mcp ${purpose} v1`));
      decipher.setAuthTag(data.subarray(data.length - 16));
      return JSON.parse(Buffer.concat([decipher.update(data.subarray(12, data.length - 16)), decipher.final()]).toString("utf8")) as T;
    } catch {
      return undefined;
    }
  }

  // Short field names keep the Entra URL short, see MAX_STATE.
  const sealRequest = (r: SignInRequest) => seal("consent", { c: r.clientId, r: r.redirectUri, s: r.state, p: r.codeChallenge, t: r.createdAt });

  function openRequest(text: string | undefined): SignInRequest | undefined {
    const v = unseal<{ c: string; r: string; s?: string; p: string; t: number }>("consent", text);
    if (!v || Date.now() - v.t > SIGN_IN_TTL_MS) return undefined;
    return { clientId: v.c, redirectUri: v.r, state: v.s, codeChallenge: v.p, createdAt: v.t };
  }

  const sealEntraState = (s: EntraSignIn) =>
    seal("entra", { h: s.clientHash, r: s.redirectUri, s: s.state, p: s.codeChallenge, k: s.verifier, b: s.binding, t: s.createdAt });

  function openEntraState(text: string | undefined): EntraSignIn | undefined {
    const v = unseal<{ h: string; r: string; s?: string; p: string; k: string; b: string; t: number }>("entra", text);
    if (!v || Date.now() - v.t > SIGN_IN_TTL_MS) return undefined;
    return { clientHash: v.h, redirectUri: v.r, state: v.s, codeChallenge: v.p, verifier: v.k, binding: v.b, createdAt: v.t };
  }

  // ---------------------------------------------------------------- Entra

  async function entraToken(form: Record<string, string>): Promise<EntraTokens> {
    const url = `${tenantAuthority}/oauth2/v2.0/token`;
    let response: Awaited<ReturnType<typeof fetch>>;
    let json: { access_token?: string; refresh_token?: string; expires_in?: number; error?: string; error_description?: string };
    try {
      response = await fetch(url, {
        method: "POST",
        body: new URLSearchParams({ client_id: config.clientId, client_secret: config.clientSecret, ...form }),
        dispatcher: shared.loginDispatcher,
        // Following a redirect would send the client secret and the user's grant on to whatever host it names.
        redirect: "manual",
        signal: AbortSignal.timeout(config.timeoutMs),
      });
      json = response.status >= 300 && response.status < 400 ? {} : ((await response.json()) as typeof json);
    } catch (error) {
      console.error(`fo-mcp: Entra did not answer the ${form.grant_type} request: ${oneLine((error as Error).message)}`);
      throw new EntraError(`Entra did not answer: ${(error as Error).message}`, false);
    }
    if (response.status >= 300 && response.status < 400) {
      await response.body?.cancel().catch(() => undefined);
      console.error(`fo-mcp: Entra answered the ${form.grant_type} request with a redirect to ${redirectHost(response.headers.get("location"), url)}, which is not followed. Check FO_AUTHORITY.`);
      throw new EntraError("Entra answered with a redirect, which is not followed", false);
    }
    if (!response.ok || !json.access_token) {
      // The full text names the request for Entra support, the client gets the AADSTS code and message only.
      const description = typeof json.error_description === "string" ? json.error_description : "no token";
      console.error(`fo-mcp: Entra refused the ${form.grant_type} request with ${response.status} ${oneLine(String(json.error ?? ""))}: ${oneLine(description)}`);
      // A 400 with an OAuth error code is Entra refusing the grant, unless the code itself says it is passing.
      // Anything else (5xx, a proxy page) may pass too.
      const passing = json.error === "temporarily_unavailable" || json.error === "server_error";
      throw new EntraError(`${json.error ?? response.status}: ${entraMessage(description)}`, response.status === 400 && !!json.error && !passing);
    }
    return {
      accessToken: json.access_token,
      refreshToken: json.refresh_token,
      expiresAt: Date.now() + (json.expires_in ?? 3600) * 1000,
      ...decodeUser(json.access_token),
    };
  }

  // ---------------------------------------------------------------- Routes

  /** What clients read at /.well-known/oauth-authorization-server. */
  const metadata: OAuthMetadata = {
    issuer: origin,
    authorization_endpoint: `${origin}/authorize`,
    token_endpoint: `${origin}/token`,
    registration_endpoint: `${origin}/register`,
    revocation_endpoint: `${origin}/revoke`,
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code", "refresh_token"],
    code_challenge_methods_supported: ["S256"],
    // Every registered client is public: PKCE and the redirect URI protect the flow, there is no secret to check.
    token_endpoint_auth_methods_supported: ["none"],
    revocation_endpoint_auth_methods_supported: ["none"],
    scopes_supported: [scope],
    authorization_response_iss_parameter_supported: true,
  };

  /** Count a request against one of the limits per address, and answer 429 once it is used up. */
  function limit(limiter: RateLimiter, kind: "page" | "json") {
    return (req: Request, res: Response, next: NextFunction) => {
      const wait = limiter.hit(clientIp(req, trustProxy));
      if (wait === undefined) return next();
      res.set("Retry-After", String(wait));
      if (kind === "page") page(res, 429, "Too many requests", `<p>Too many sign in requests from your network. Try again in ${wait} seconds.</p>`);
      else res.status(429).json({ error: "temporarily_unavailable", error_description: `Too many requests from this address, try again in ${wait} seconds` });
    };
  }

  /** Send the browser back to the client. Every authorization response names this server as its issuer (RFC 9207). */
  function backToClient(res: Response, signIn: { redirectUri: string; state?: string }, params: Record<string, string>, status = 302): void {
    const back = new URL(signIn.redirectUri);
    for (const [name, value] of Object.entries(params)) back.searchParams.set(name, value);
    if (signIn.state) back.searchParams.set("state", signIn.state);
    back.searchParams.set("iss", origin);
    res.set(REDIRECT_HEADERS).redirect(status, back.toString());
  }

  /**
   * Send the browser to Entra with the sign in sealed into the state, bound to this browser by a cookie. A second click
   * on Approve starts a second sign in with its own cookie, the first one simply expires.
   *
   * Right after a click on Approve the user has seen a page, and Entra may sign in silently. For a `remembered`
   * approval this server showed none, so Entra is asked for its account picker instead: a sign in the user did not
   * start, from a link someone else sent for a client this browser approved once, is then visible and can be closed
   * rather than finishing with no page at all.
   */
  function toEntra(res: Response, request: SignInRequest, status: number, remembered = false): void {
    const value = random();
    const verifier = random();
    // The time at the Entra page counts from here, not from the consent page.
    const signIn: EntraSignIn = {
      clientHash: s256(request.clientId), redirectUri: request.redirectUri, state: request.state, codeChallenge: request.codeChallenge,
      verifier, binding: s256(value), createdAt: Date.now(),
    };
    res.cookie(bindingCookie(signIn.binding), value, cookieOptions(SIGN_IN_TTL_MS));
    const entra = new URL(`${tenantAuthority}/oauth2/v2.0/authorize`);
    entra.search = new URLSearchParams({
      client_id: config.clientId,
      response_type: "code",
      redirect_uri: `${origin}/callback`,
      response_mode: "query",
      scope: `${entraScope} openid profile offline_access`,
      state: sealEntraState(signIn),
      code_challenge: s256(verifier),
      code_challenge_method: "S256",
      ...(remembered ? { prompt: "select_account" } : {}),
    }).toString();
    res.set(REDIRECT_HEADERS).redirect(status, entra.toString());
  }

  function consentPage(req: Request, res: Response, request: SignInRequest, clientName: string | undefined): void {
    const sealed = sealRequest(request);
    const csrf = csrfToken(req, res, sealed);
    const who = clientName ? `<strong>${escapeHtml(clientName)}</strong>` : "An MCP client without a name";
    const access = ["Read Dynamics 365 Finance and Operations data"];
    if (allowWrites) access.push(writeRole ? `Create and change records, if your account has the ${escapeHtml(writeRole)} role` : "Create and change records");
    // Referrer-Policy: same-origin makes the browser send this page's origin with the form, which /consent checks. Under
    // no-referrer it would send Origin: null. The page loads nothing and links only to /forget here, so no referrer
    // leaves the site. The form action is absolute: the page is also served at /authorize/, and a relative action
    // would post from there to /authorize/consent, which nothing answers.
    page(res, 200, "Allow access to Finance and Operations", `
<h1>Allow access to Dynamics 365 Finance and Operations?</h1>
<p>${who} wants to work with Finance and Operations data as you. The application chose this name itself.</p>
<dl><dt>Sends the result to</dt><dd><code>${escapeHtml(new URL(request.redirectUri).origin)}</code></dd>
<dt>Gets</dt><dd>${access.join("<br>")}<br>Always limited to your own F&amp;O security roles.</dd></dl>
<p>Approve only if you just added or reconnected this connector yourself. You then sign in with Microsoft.</p>
<form method="post" action="/consent"><input type="hidden" name="request" value="${escapeHtml(sealed)}"><input type="hidden" name="csrf" value="${escapeHtml(csrf)}">
<button type="submit" name="action" value="approve">Approve</button><button type="submit" name="action" value="cancel">Cancel</button></form>
<p class="note">This browser remembers the approval for 30 days. Later sign ins of this connector skip this page and Microsoft asks you to pick your account instead.
<a href="/forget">Forget the approvals of this browser</a>.</p>`, { "Referrer-Policy": "same-origin" });
  }

  const router: Router = express.Router();
  router.use(express.urlencoded({ extended: false }));
  router.use(express.json());
  // Token responses must not be cached anywhere on the way (RFC 6749 section 5.1).
  router.use(["/token", "/revoke"], (_req, res, next) => {
    res.set({ "Cache-Control": "no-store", Pragma: "no-cache" });
    next();
  });

  for (const path of ["/.well-known/oauth-authorization-server", "/.well-known/oauth-authorization-server/mcp", "/.well-known/openid-configuration"]) {
    router.get(path, (_req, res) => {
      res.json(metadata);
    });
  }

  // Dynamic client registration. Nothing is stored: the client id carries the registration, signed by this server.
  router.post("/register", limit(limits.register, "json"), (req: Request, res: Response) => {
    const body = (req.body ?? {}) as { redirect_uris?: unknown; client_name?: unknown };
    const uris = Array.isArray(body.redirect_uris) ? body.redirect_uris : [];
    if (!uris.length || !uris.every((u) => typeof u === "string" && u.length <= MAX_FIELD && redirectAllowed(u))) {
      res.status(400).json({ error: "invalid_redirect_uri", error_description: "Only localhost and Claude redirect URIs are accepted." });
      return;
    }
    const name = typeof body.client_name === "string" ? body.client_name.trim() : undefined;
    if ((body.client_name !== undefined && body.client_name !== null && typeof body.client_name !== "string") || (name && !validClientName(name))) {
      res.status(400).json({ error: "invalid_client_metadata", error_description: "client_name must be at most 100 printable characters." });
      return;
    }
    const { clientId, issuedAt } = clientIdFor({ name: name || undefined, redirectUris: uris as string[] });
    if (clientId.length > MAX_CLIENT_ID) {
      res.status(400).json({ error: "invalid_client_metadata", error_description: "Too many or too long redirect URIs." });
      return;
    }
    res.status(201).json({
      client_id: clientId,
      client_id_issued_at: issuedAt,
      client_name: name || "MCP client",
      redirect_uris: uris,
      token_endpoint_auth_method: "none",
      grant_types: ["authorization_code", "refresh_token"],
      response_types: ["code"],
    });
  });

  // Step 1: the client sends the user here. A client this browser approved before goes on to Entra, any other gets the consent page.
  router.get("/authorize", limit(limits.authorize, "page"), (req: Request, res: Response) => {
    sweep();
    if (req.originalUrl.length > MAX_AUTHORIZE_URL) {
      page(res, 414, "Request too long", "<p>The authorization request is too long.</p>");
      return;
    }
    // Without a valid client and one of its redirect URIs there is nowhere safe to send an error, so the browser shows it.
    const clientId = field(req.query, "client_id");
    const client = readClient(clientId);
    if (!client) {
      page(res, 400, "Connector not registered", "<h1>This connector is not registered with this server</h1>" +
        "<p>The server does not know this MCP client, or no longer does. Remove the connector in your MCP client, add it again and sign in once more.</p>");
      return;
    }
    const redirectUri = field(req.query, "redirect_uri");
    if (!redirectUri || !redirectAllowed(redirectUri) || !redirectRegistered(client.redirectUris, redirectUri)) {
      page(res, 400, "Unknown redirect URI", "<h1>Unknown redirect URI</h1>" +
        "<p>The redirect_uri is missing or is not one this MCP client registered. Remove the connector and add it again.</p>");
      return;
    }
    const state = field(req.query, "state");
    const fail = (error: string, description: string) => backToClient(res, { redirectUri, state }, { error, error_description: description });
    if (field(req.query, "response_type") !== "code") return fail("unsupported_response_type", "Only response_type=code is supported");
    const codeChallenge = field(req.query, "code_challenge");
    if (!codeChallenge || !/^[A-Za-z0-9_-]{43}$/.test(codeChallenge) || field(req.query, "code_challenge_method") !== "S256") {
      return fail("invalid_request", "A S256 code_challenge is required");
    }
    const requested = (field(req.query, "scope") ?? "").split(" ").filter(Boolean);
    if (requested.some((s) => s !== scope && !OIDC_SCOPES.includes(s))) return fail("invalid_scope", `Only ${scope} can be requested`);
    if (state !== undefined && Buffer.byteLength(JSON.stringify(state)) - 2 > MAX_STATE) return fail("invalid_request", `state may be at most ${MAX_STATE} characters`);
    // Nothing is stored: the request travels sealed in the consent form, or straight on in the state sent to Entra.
    const request: SignInRequest = { clientId: clientId!, redirectUri, state, codeChallenge, createdAt: Date.now() };
    if (approvedClients(req).includes(handle(clientId!))) return toEntra(res, request, 302, true);
    consentPage(req, res, request, client.name);
  });

  // Step 2: the user approves or cancels on the consent page.
  router.post("/consent", limit(limits.consent, "page"), (req: Request, res: Response) => {
    // The CSRF cookie goes along with a form another host of the same site posts here, so the origin decides first.
    if (!fromOwnPage(req)) {
      page(res, 403, "Approval refused", "<p>This approval did not come from the approval page of this server. Start the sign in again from your MCP client.</p>");
      return;
    }
    const sealed = field(req.body, "request");
    const request = openRequest(sealed);
    if (!request || !csrfValid(req, sealed!, field(req.body, "csrf"))) {
      page(res, 400, "Sign in expired", "<p>This approval page has expired or was opened in another browser. Start the sign in again from your MCP client.</p>");
      return;
    }
    const action = field(req.body, "action");
    if (action === "cancel") {
      backToClient(res, request, { error: "access_denied", error_description: "The user cancelled the sign in" }, 303);
      return;
    }
    if (action !== "approve") {
      page(res, 400, "Unknown action", "<p>Use the Approve or Cancel button.</p>");
      return;
    }
    rememberConsent(req, res, request.clientId);
    toEntra(res, request, 303);
  });

  // A browser forgets every approval it remembers, so each client gets the consent page again. A link on that page leads
  // here. Clearing the cookie needs no form: the worst a link from elsewhere can do is show the user the page once more.
  router.get("/forget", limit(limits.consent, "page"), (_req: Request, res: Response) => {
    res.clearCookie(consentCookie, cookieOptions());
    page(res, 200, "Approvals forgotten", "<h1>This browser no longer remembers any approval</h1>" +
      "<p>The next sign in of every connector shows the approval page again. Start the sign in from your MCP client when you want to connect.</p>");
  });

  // Step 3: Entra sends the user back with a code, we exchange it and send the user on to the client with our own code.
  router.get("/callback", limit(limits.callback, "page"), async (req: Request, res: Response) => {
    sweep();
    const sealed = field(req.query, "state");
    const signIn = openEntraState(sealed);
    const used = s256(sealed ?? "");
    if (!signIn || usedStates.has(used)) {
      page(res, 400, "Sign in expired", "<p>Unknown or expired sign in. Start again from your MCP client.</p>");
      return;
    }
    // Only the browser that left for Entra holds the cookie. Without it a code from someone else's sign in could be planted here.
    const name = bindingCookie(signIn.binding);
    const cookie = cookies(req).get(name);
    if (!cookie || !same(s256(cookie), signIn.binding)) {
      page(res, 400, "Different browser",
        "<p>This sign in was started in another browser, or it is over. Start again from your MCP client and finish the sign in in the browser that opens.</p>");
      return;
    }
    res.clearCookie(name, cookieOptions());
    const entraCode = field(req.query, "code");
    if (!entraCode) {
      const error = field(req.query, "error") ?? "access_denied";
      const description = field(req.query, "error_description");
      if (description) console.error(`fo-mcp: Entra sign in failed: ${oneLine(error)}: ${oneLine(description)}`);
      backToClient(res, signIn, { error, error_description: description ? entraMessage(description) : "Sign in was cancelled" });
      return;
    }
    try {
      const tokens = await entraToken({ grant_type: "authorization_code", code: entraCode, redirect_uri: `${origin}/callback`, code_verifier: signIn.verifier });
      // Only a state Entra accepted a code for is remembered. Anything else anyone can repeat, and it would fill memory.
      usedStates.set(used, signIn.createdAt + SIGN_IN_TTL_MS);
      if (!tokens.oid) {
        // Sessions, caches and the audit log key on the object ID. A token without one has no user the server can tell apart.
        console.error("fo-mcp: Entra issued a user token without an oid claim, the sign in was refused");
        backToClient(res, signIn, { error: "server_error", error_description: "Entra sign in failed: the token has no oid claim, so the user cannot be identified" });
        return;
      }
      const code = random();
      codes.set(code, { ...tokens, clientHash: signIn.clientHash, redirectUri: signIn.redirectUri, codeChallenge: signIn.codeChallenge, createdAt: Date.now() });
      backToClient(res, signIn, { code });
    } catch (error) {
      backToClient(res, signIn, { error: "server_error", error_description: `Entra sign in failed: ${(error as Error).message}` });
    }
  });

  /** Issue a new pair. `replaced` is the refresh token a refresh exchanged for it, see Session. */
  function issue(clientId: string, tokens: EntraTokens, family: string, replaced?: string): Record<string, unknown> {
    const access = random();
    // The family, a random part and a signature over both, see exchangedIn.
    const unsigned = `${family}.${random()}`;
    const refresh = `${unsigned}.${sign("refresh", unsigned)}`;
    const now = Date.now();
    const expiresAt = Math.min(tokens.expiresAt, now + SESSION_TTL_MS);
    // Without an Entra refresh token there is nothing to refresh with, so the refresh token ends with the access token.
    const refreshExpiresAt = tokens.refreshToken ? now + REFRESH_TTL_MS : expiresAt;
    const { accessToken, refreshToken, oid, user, name, roles } = tokens;
    sessions.set(access, { accessToken, refreshToken, oid, user, name, roles, expiresAt, clientId, scope, refresh, refreshExpiresAt, family, replaced });
    refreshTokens.set(refresh, access);
    families.set(family, access);
    return { access_token: access, token_type: "Bearer", expires_in: Math.floor((expiresAt - now) / 1000), refresh_token: refresh, scope };
  }

  // Step 4: the client trades the code for tokens. PKCE is verified here, Entra never sees the client.
  router.post("/token", limit(limits.token, "json"), async (req: Request, res: Response) => {
    sweep();
    const grantType = field(req.body, "grant_type");
    if (grantType !== "authorization_code" && grantType !== "refresh_token") {
      res.status(400).json({ error: "unsupported_grant_type" });
      return;
    }
    const clientId = field(req.body, "client_id");
    if (!readClient(clientId)) {
      // invalid_client makes MCP clients drop the registration and register again, which is the way out.
      res.status(401).json({ error: "invalid_client", error_description: "Unknown client_id. Register the client again." });
      return;
    }
    if (grantType === "authorization_code") {
      const code = field(req.body, "code");
      const used = code ? usedCodes.get(code) : undefined;
      if (used) {
        // A code presented twice was copied. What its first exchange issued is revoked (RFC 6749 section 4.1.2).
        if (used.family) revokeFamily(used.family);
        res.status(400).json({ error: "invalid_grant", error_description: "Code was already used, the sign in it started is revoked. Sign in again." });
        return;
      }
      const issued = code ? codes.get(code) : undefined;
      if (!issued) {
        res.status(400).json({ error: "invalid_grant", error_description: "Unknown or expired code" });
        return;
      }
      codes.delete(code!);
      const exchange: UsedCode = { until: issued.createdAt + CODE_TTL_MS };
      usedCodes.set(code!, exchange);
      const verifier = field(req.body, "code_verifier");
      if (issued.clientHash !== s256(clientId!) || issued.redirectUri !== field(req.body, "redirect_uri") || !verifier || s256(verifier) !== issued.codeChallenge) {
        res.status(400).json({ error: "invalid_grant", error_description: "client_id, redirect_uri or code_verifier does not match" });
        return;
      }
      exchange.family = random();
      // /callback issues no code without an oid.
      makeRoom(issued.oid!);
      res.json(issue(clientId!, issued, exchange.family));
      return;
    }
    const refresh = field(req.body, "refresh_token");
    const running = refresh ? refreshing.get(refresh) : undefined;
    if (running) {
      // Two tool calls after an idle hour both get 401 and both refresh with the same token. They get the same new pair,
      // a second answer of invalid_grant would make the client throw its tokens away and send the user to sign in.
      if (running.clientId !== clientId) {
        res.status(400).json({ error: "invalid_grant", error_description: "Unknown or expired refresh token, sign in again" });
        return;
      }
      const { status, body } = await running.answer;
      res.status(status).json(body);
      return;
    }
    const access = refresh ? refreshTokens.get(refresh) : undefined;
    const session = access ? sessions.get(access) : undefined;
    const used = !access && refresh ? retired.get(refresh) : undefined;
    if (used && used.clientId === clientId && Date.now() - used.retiredAt <= REUSE_GRACE_MS && families.get(used.family) === used.answer.body.access_token) {
      // A parallel request that missed the exchange by a moment gets the same new pair.
      res.status(used.answer.status).json(used.answer.body);
      return;
    }
    const copied = !access && refresh ? exchangedIn(refresh) : undefined;
    if (copied && copied.clientId === clientId) {
      // The same refresh token twice means it was copied. End the sign in, the owner signs in again.
      revokeFamily(copied.family);
      res.status(400).json({ error: "invalid_grant", error_description: "Refresh token was already used, this sign in is revoked. Sign in again." });
      return;
    }
    if (!session || session.clientId !== clientId || session.refreshExpiresAt < Date.now()) {
      res.status(400).json({ error: "invalid_grant", error_description: "Unknown or expired refresh token, sign in again" });
      return;
    }
    /** Replace the old pair with a new one in the same family and remember the old refresh token. */
    const rotate = (tokens: EntraTokens): TokenAnswer => {
      // A replay can revoke the family while Entra answers this refresh. Then the answer must not bring it back.
      if (families.get(session.family) !== access) {
        return { status: 400, body: { error: "invalid_grant", error_description: "This sign in was revoked. Sign in again." } };
      }
      // A refreshed token for another user, or for none, must never continue this sign in.
      if (!tokens.oid || tokens.oid !== session.oid) {
        revokeFamily(session.family);
        return { status: 400, body: { error: "invalid_grant", error_description: "Entra answered the refresh for another user. Sign in again." } };
      }
      sessions.delete(access!);
      refreshTokens.delete(refresh!);
      // One entry per sign in: only the latest exchanged token can still pass the grace, and a client that chains
      // refreshes must not grow the map with every one of them. Each entry then belongs to a live pair, so the map stays
      // within MAX_SIGN_INS like the sessions. An older token is still recognised as a replay, by its family.
      if (session.replaced) retired.delete(session.replaced);
      const answer = { status: 200, body: issue(session.clientId, tokens, session.family, refresh!) };
      retired.set(refresh!, { family: session.family, clientId: session.clientId, retiredAt: Date.now(), answer });
      return answer;
    };
    if (!session.refreshToken) {
      // Nothing to refresh with, hand out the same Entra token under a new pair until it expires.
      const rotated = rotate(session);
      res.status(rotated.status).json(rotated.body);
      return;
    }
    const answer = (async () => {
      try {
        const tokens = await entraToken({ grant_type: "refresh_token", refresh_token: session.refreshToken!, scope: `${entraScope} openid profile offline_access` });
        // Single use: once the new pair exists the old refresh token is retired.
        return rotate(tokens);
      } catch (error) {
        if (error instanceof EntraError && error.grantError) {
          revokeFamily(session.family);
          return { status: 400, body: { error: "invalid_grant", error_description: `Entra refused the refresh, sign in again: ${error.message}` } };
        }
        // Entra could not answer. The refresh token stays valid, so the client can try again instead of signing in.
        return { status: 503, body: { error: "temporarily_unavailable", error_description: (error as Error).message } };
      }
    })();
    refreshing.set(refresh!, { clientId, answer });
    try {
      const { status, body } = await answer;
      res.status(status).json(body);
    } finally {
      refreshing.delete(refresh!);
    }
  });

  /**
   * The live sign in a refresh token was exchanged in, however long ago. A refresh token starts with its family, so
   * every token a sign in ever issued names it and none has to be stored to be recognised: a thief who refreshes a
   * second time cannot push the stolen token out of anything. The signature says that this server issued the token
   * as it stands, so a token cut short in a log or mangled by a client names no sign in and ends none. Only called
   * for a token that is not the current one of any sign in.
   */
  function exchangedIn(token: string): { family: string; clientId: string } | undefined {
    const match = /^(([\w-]+)\.[\w-]+)\.([\w-]+)$/.exec(token);
    if (!match || !same(match[3], sign("refresh", match[1]))) return undefined;
    const current = sessions.get(families.get(match[2]) ?? "");
    return current ? { family: match[2], clientId: current.clientId } : undefined;
  }

  /** The sign in an access or refresh token belongs to, also a refresh token that was exchanged already. */
  function familyOf(token: string): { family: string; clientId: string } | undefined {
    const session = sessions.get(token) ?? sessions.get(refreshTokens.get(token) ?? "");
    return session ? { family: session.family, clientId: session.clientId } : exchangedIn(token);
  }

  // Token revocation (RFC 7009). Revoking either token of a sign in ends the whole sign in. token_type_hint is not needed,
  // both kinds are looked up.
  router.post("/revoke", limit(limits.revoke, "json"), (req: Request, res: Response) => {
    sweep();
    const token = field(req.body, "token");
    const clientId = field(req.body, "client_id");
    const found = token ? familyOf(token) : undefined;
    if (found && (!clientId || clientId === found.clientId)) revokeFamily(found.family);
    // Always 200, also for an unknown token, so the answer tells nothing about which tokens exist.
    res.status(200).end();
  });

  /** Resolve one of our opaque tokens. Returns undefined when the token is not ours, so a JWT check can follow. */
  function verifyProxyToken(token: string): AuthInfo | undefined {
    const session = sessions.get(token);
    if (!session) return undefined;
    if (session.expiresAt < Date.now()) throw new InvalidTokenError("Token expired, refresh it or sign in again");
    return {
      // The Entra token goes into AuthInfo, so the on-behalf-of exchange for F&O can use it. It never leaves the server.
      token: session.accessToken,
      clientId: session.clientId,
      scopes: session.scope.split(" "),
      expiresAt: Math.floor(session.expiresAt / 1000),
      extra: { oid: session.oid, user: session.user, name: session.name, roles: session.roles },
    };
  }

  return { router, metadata, verifyProxyToken };
}
