import { AsyncLocalStorage } from "node:async_hooks";
import { createHash } from "node:crypto";
import { lookup } from "node:dns";
import { readFileSync } from "node:fs";
import { isIP, type LookupFunction } from "node:net";
import { resolve } from "node:path";
import type { ConnectionOptions } from "node:tls";
// undici's own fetch instead of Node's global one, so the dispatcher option (proxy, certificate, fixed IP) is typed and guaranteed.
import { EnvHttpProxyAgent, fetch, type Dispatcher, type buildConnector } from "undici";
import { version } from "./config.js";

/** Everything the server needs to talk to one F&O environment. Loaded from .env, see .env.example. */
export interface FoConfig {
  url: string;
  /**
   * How the model and the user know this environment, PROD or TEST for example, in the instructions, the write tool
   * descriptions and the confirmation before a write. The host of FO_URL unless FO_NAME is set.
   */
  name: string;
  tenantId: string;
  clientId: string;
  clientSecret: string;
  /** Entra authority, https://login.microsoftonline.com for the public cloud. */
  authority: string;
  /** Default legal entity for company specific entities. Empty means all companies for reads and an explicit dataAreaId for writes. */
  company?: string;
  /** Expose create_record and update_record. Off by default. */
  allowWrites: boolean;
  /** Collection names Claude may use. Empty means every OData enabled entity the F&O user can see. */
  entities: string[];
  /** Collection names create_record and update_record may use. Empty means every entity the server may read. */
  writeEntities: string[];
  /** Write one audit line per tool call. On unless FO_AUDIT=0. */
  audit: boolean;
  /** Put the written values into the audit lines as well (FO_AUDIT_VALUES=1). */
  auditValues: boolean;
  /** Skip certificate validation for the F&O host. Only for the LCS VHD one-box. */
  insecureTls: boolean;
  /** PEM file with the F&O server certificate, the safer alternative to insecureTls. */
  caFile?: string;
  /** Fixed IP address for the F&O host name when it does not resolve on this machine. */
  hostIp?: string;
  /** Language for labels, for example en-US. */
  language: string;
  /** Time budget of one tool call, shared by all the requests it makes. MCP clients give up after 60 seconds. */
  timeoutMs: number;
}

export function loadConfig(env: NodeJS.ProcessEnv, baseDir = process.cwd()): FoConfig {
  const required = (name: string): string => {
    const value = env[name]?.trim();
    if (!value) throw new Error(`Missing environment variable ${name}. Copy .env.example to .env and fill in the values.`);
    return value;
  };
  const flag = (name: string): boolean => {
    const value = env[name]?.trim().toLowerCase() ?? "";
    if (["", "0", "false", "no", "off"].includes(value)) return false;
    if (["1", "true", "yes", "on"].includes(value)) return true;
    throw new Error(`${name} must be 1 or 0, got '${env[name]}'`);
  };
  const url = required("FO_URL").replace(/\/+$/, "");
  if (!/^https:\/\/[^/]+$/.test(url)) throw new Error(`FO_URL must look like https://host, got '${url}'`);
  const authority = (env.FO_AUTHORITY?.trim() || "https://login.microsoftonline.com").replace(/\/+$/, "");
  if (!authority.startsWith("https://")) throw new Error(`FO_AUTHORITY must start with https://, got '${authority}'`);
  const hostIp = env.FO_HOST_IP?.trim() || undefined;
  if (hostIp && !isIP(hostIp)) throw new Error(`FO_HOST_IP must be an IPv4 or IPv6 address without brackets, got '${hostIp}'`);
  const timeoutMs = env.FO_TIMEOUT_MS?.trim() ? Number(env.FO_TIMEOUT_MS) : 50_000;
  if (!Number.isInteger(timeoutMs) || timeoutMs < 1000 || timeoutMs > 60_000) {
    throw new Error(`FO_TIMEOUT_MS must be a whole number of milliseconds between 1000 and 60000, got '${env.FO_TIMEOUT_MS}'`);
  }
  const list = (name: string): string[] => (env[name] ?? "").split(",").map((e) => e.trim()).filter(Boolean);
  const entities = list("FO_ENTITIES");
  const writeEntities = list("FO_WRITE_ENTITIES");
  // A write entity the server may not even read would be refused on every call, so say so at start.
  const unreadable = entities.length ? writeEntities.filter((w) => !entities.some((e) => e.toLowerCase() === w.toLowerCase())) : [];
  if (unreadable.length) throw new Error(`Every entity in FO_WRITE_ENTITIES must be on FO_ENTITIES too, missing there: ${unreadable.join(", ")}`);
  return {
    url,
    name: env.FO_NAME?.trim() || new URL(url).host,
    tenantId: required("FO_TENANT_ID"),
    clientId: required("FO_CLIENT_ID"),
    clientSecret: required("FO_CLIENT_SECRET"),
    authority,
    company: env.FO_COMPANY?.trim() || undefined,
    allowWrites: flag("FO_ALLOW_WRITES"),
    entities,
    writeEntities,
    audit: env.FO_AUDIT?.trim() ? flag("FO_AUDIT") : true,
    auditValues: flag("FO_AUDIT_VALUES"),
    insecureTls: flag("FO_INSECURE_TLS"),
    caFile: env.FO_CA_FILE?.trim() ? resolve(baseDir, env.FO_CA_FILE.trim()) : undefined,
    hostIp,
    language: env.FO_LANGUAGE?.trim() || "en-US",
    timeoutMs,
  };
}

/** An error from F&O, Entra or the network, with a message that is safe to show to the model. */
export class FoError extends Error {
  constructor(
    message: string,
    public readonly status?: number,
    /** The message for the audit log, when the message itself shows values of a record. */
    public readonly logMessage?: string,
    /**
     * True when a write went out and its outcome is not known: no answer within the budget, a cancel, a broken
     * connection or a gateway error after the request was sent. F&O may or may not have done the write.
     */
    public readonly outcomeUnknown = false,
    /** True when the connection failed before the request could go out, ECONNREFUSED for example, so F&O never got it. */
    public readonly notSent = false
  ) {
    super(message);
    this.name = "FoError";
  }
}

/** One row of /Metadata/DataEntities. */
export interface DataEntity {
  Name: string;
  PublicEntityName: string;
  PublicCollectionName: string;
  LabelId: string;
  DataServiceEnabled: boolean;
  DataManagementEnabled: boolean;
  EntityCategory: string;
  IsReadOnly: boolean;
}

/** One row of /Metadata/PublicEntities, the OData view of an entity with its fields. */
export interface PublicEntity {
  Name: string;
  EntitySetName: string;
  LabelId: string;
  IsReadOnly: boolean;
  Properties: EntityProperty[];
  NavigationProperties: Array<{ Name: string; RelatedEntity: string; RelatedRelationName: string; Cardinality: string }>;
}

export interface EntityProperty {
  Name: string;
  /** For enums the X++ enum name, for example NoYes or SalesStatus. */
  TypeName: string;
  /** String, Int32, Int64, Real, Enum, Date, UtcDateTime, Time, Guid ... */
  DataType: string;
  LabelId: string;
  IsKey: boolean;
  IsMandatory: boolean;
  AllowEdit: boolean;
  AllowEditOnCreate: boolean;
}

/** One row of /Metadata/PublicEnumerations: an X++ enum with its elements, for example NoYes with No and Yes. */
export interface PublicEnumeration {
  Name: string;
  LabelId: string;
  Members: Array<{ Name: string; LabelId: string; Value: number; ConfigurationEnabled: boolean }>;
}

/** An entity resolved from any of its names, with the metadata the tools need. */
export interface EntityInfo {
  collection: string;
  details: PublicEntity;
  /** True when the entity has a dataAreaId field, so its records belong to a legal entity. */
  companySpecific: boolean;
}

export interface QueryOptions {
  filter?: string;
  select?: string;
  orderby?: string;
  expand?: string;
  top?: number;
  skip?: number;
  count?: boolean;
  /** Adds the F&O specific cross-company=true option. */
  crossCompany?: boolean;
}

const METADATA_CACHE_TTL_MS = 10 * 60_000; // refresh entity lists after 10 minutes
const RETRY_AFTER_MS = 30_000; // after a failed refresh, ask F&O again at most every 30 seconds
/**
 * A name that is not on the entity list refreshes the list behind the answer, so an entity deployed during a session
 * shows up before the ten minutes are over, but at most this often per identity: the list is a download of several
 * MB on a real environment and models guess entity names often.
 */
const MISS_REFRESH_MS = 3 * 60_000;
const DATA_ENTITIES_NAMESPACE = "Microsoft.Dynamics.DataEntities.";

/**
 * What a request other than a GET does, which decides what a failure after sending it may mean. An action is one that
 * only reads, such as the version actions of environment_info, so it is sent however little of the budget is left.
 */
export type WriteKind = "create" | "update" | "action";
type FoRequestInit = {
  method?: string;
  body?: unknown;
  /** For a POST or PATCH. Defaults to create for POST and update for anything else. */
  kind?: WriteKind;
  /** Called just before the request goes out, every time it does, so the caller knows that F&O may have received it. */
  onSend?: () => void;
};
type Cached<T> = { value: T; fetchedAt: number };
/** Which one-time retries a request may still make: after a 401 with a fresh token, after throttling once Retry-After has passed. */
type Retries = { unauthorized: boolean; throttled: boolean };

/** Returns an access token for F&O and how long it is valid, in seconds. */
export type TokenSource = () => Promise<{ accessToken: string; expiresIn: number }>;

/** What one F&O identity has read from the Metadata service and LegalEntities, kept for ten minutes. */
class FoCaches {
  entityCache: Cached<DataEntity[]> | undefined;
  entityFetch: Promise<DataEntity[]> | undefined;
  entityRefreshFailedAt = 0;
  /** When a name that is not on the list last started a refresh behind its answer, whatever became of it. */
  entityMissRefreshAt = 0;
  /** A list answer that arrived and was refused here, one over the size limit for example, and when. See listEntities. */
  entityRefusal: { error: unknown; at: number } | undefined;
  /** In order of use, the least recently used first, and at most MAX_PUBLIC_ENTITIES of them. */
  readonly publicEntityCache = new Map<string, Cached<PublicEntity>>();
  companyCache: Cached<Array<{ id: string; name: string }>> | undefined;
  usedAt = Date.now();
}

/** Caches of a user who made no call for this long are dropped. */
const CACHE_IDLE_MS = 60 * 60_000;

/**
 * Entity details one identity keeps. A wide entity takes tens of KB once parsed, and an agent that walks hundreds of
 * entities would otherwise keep all of them for as long as the user stays active.
 */
const MAX_PUBLIC_ENTITIES = 200;

/**
 * Labels and enum definitions the process keeps for every identity together. describe_entity reads a label for each
 * field it shows, so a team that walks hundreds of entities over weeks would otherwise leave every label of the
 * environment in memory until a restart.
 */
const MAX_SHARED_ENTRIES = 5_000;

/**
 * Bytes of F&O answers that all tool calls together may hold at once, Metadata answers included. Every answer is
 * parsed and copied after it is read, so a few dozen wide pages at the same time would otherwise take the process
 * past the memory of a small replica and end every user's sign in with it.
 */
const MAX_BYTES_HELD = 96_000_000;

/** The abort reason of FoShared.shutdown, so a call that is stopped can say why. */
const SHUTDOWN = Symbol("shutdown");

/**
 * Tool calls that may run at once for one F&O identity and for the whole process. F&O throttles requests when its web
 * servers are under load, and a model that fires dozens of parallel queries would only queue them behind each other and
 * run out of time. Claude Code sends calls of read-only tools in parallel, often more than six at once, so a call past
 * the limit of its identity waits for one of them to end, within its own time budget. The queue is short: past
 * MAX_WAITING_PER_IDENTITY waiting calls of one identity a call is refused at once. So is a call while MAX_CALLS run.
 * Only an identity with all its places taken has a queue. MAX_CALLS leaves room for 8 of them, so at most 80 calls wait
 * on the whole server.
 */
const MAX_CALLS_PER_IDENTITY = 6;
const MAX_WAITING_PER_IDENTITY = 10;
const MAX_CALLS = 48;

/**
 * Everything that can be shared by all clients of one environment: the HTTP dispatchers and the
 * metadata caches. The stdio server has one client, the remote server has one client per user.
 */
export class FoShared {
  /** Dispatcher for F&O. Honours HTTPS_PROXY and NO_PROXY plus the certificate options. With FO_HOST_IP the F&O host bypasses the proxy. */
  readonly dispatcher: Dispatcher;
  /** Dispatcher for the Entra token endpoint. Normal DNS and normal certificate validation. */
  readonly loginDispatcher: Dispatcher = new EnvHttpProxyAgent();
  /**
   * Caches per F&O identity. F&O decides per user what the metadata and the legal entities show, so a
   * user must never be answered from what another user's token returned.
   */
  private readonly caches = new Map<string, FoCaches>();
  /**
   * Labels by language and id, and enum definitions by name. F&O does not secure either, every user gets the same
   * answer, so one copy serves every identity of the environment. Kept for ten minutes like the rest, in order of use
   * with the least recently used first and at most MAX_SHARED_ENTRIES of each.
   */
  readonly labelCache = new Map<string, Cached<string>>();
  readonly enumCache = new Map<string, Cached<PublicEnumeration | undefined>>();
  /** Tool calls running now per F&O identity, and their total. See enterCall. */
  private readonly callsRunning = new Map<string, number>();
  private callsTotal = 0;
  /** Given to shutdown, called whenever the last running tool call leaves. */
  private onIdle: (() => void) | undefined;
  /** Tool calls waiting for a place per F&O identity, in order of arrival, each as the function that lets it start. */
  private readonly callsWaiting = new Map<string, Array<() => void>>();
  /**
   * Parsed /Metadata/DataEntities lists by a hash of the answer. Identities that get the same answer share one list
   * instead of holding a copy of about 2 MB each. Lists no identity uses any more are dropped, see shareEntityList.
   */
  private readonly entityLists = new Map<string, DataEntity[]>();
  /** Bytes of F&O answers held now, see MAX_BYTES_HELD. */
  private bytesHeld = 0;
  /** Aborted by shutdown. Every tool call listens to it next to the client's own cancel signal. */
  private readonly stopController = new AbortController();
  /** Aborted once the grace that shutdown gives the writes already sent to F&O is over. A sent write listens to it instead. */
  private readonly stopWritesController = new AbortController();

  /** The caches of one identity, the Entra object ID of a signed in user or "service" for client credentials. */
  cachesFor(key: string): FoCaches {
    const now = Date.now();
    for (const [k, v] of this.caches) if (k !== key && now - v.usedAt > CACHE_IDLE_MS) this.caches.delete(k);
    let caches = this.caches.get(key);
    if (!caches) this.caches.set(key, (caches = new FoCaches()));
    caches.usedAt = now;
    return caches;
  }

  /**
   * Count a tool call of one F&O identity in, or fail with why it may not start. Run it inside FoClient.withBudget:
   * past MAX_CALLS_PER_IDENTITY the call waits until a call of the same identity ends and hands its place on, within the
   * time budget and the cancel signal of the waiting call. A call that stops waiting leaves the queue, so it never takes
   * a place it can no longer use. Every call that was counted in must be counted out with leaveCall, also when it fails.
   */
  async enterCall(identity: string): Promise<void> {
    const running = this.callsRunning.get(identity) ?? 0;
    if (running < MAX_CALLS_PER_IDENTITY) {
      if (this.callsTotal >= MAX_CALLS) throw new FoError("Too many tool calls at once on this server, wait for the running ones.");
      this.callsRunning.set(identity, running + 1);
      this.callsTotal++;
      return;
    }
    const call = deadline.getStore();
    const queue = this.callsWaiting.get(identity) ?? [];
    if (!call || queue.length >= MAX_WAITING_PER_IDENTITY) {
      throw new FoError("Too many tool calls at once for this user, wait for the running ones.");
    }
    if (call.signal?.aborted) throw cancelled(call.signal);
    this.callsWaiting.set(identity, queue);
    await new Promise<void>((resolve, reject) => {
      const leave = () => {
        clearTimeout(timer);
        call.signal?.removeEventListener("abort", onAbort);
        const at = queue.indexOf(start);
        if (at < 0) return;
        queue.splice(at, 1);
        if (!queue.length && this.callsWaiting.get(identity) === queue) this.callsWaiting.delete(identity);
      };
      // Called by leaveCall of a running call, whose place this one takes over: the counts stay as they are.
      const start = () => {
        leave();
        resolve();
      };
      const onAbort = () => {
        leave();
        reject(cancelled(call.signal));
      };
      const timer = setTimeout(() => {
        leave();
        reject(
          new FoError(
            `No place for this tool call within the ${this.config.timeoutMs / 1000} s a tool call may take: ${MAX_CALLS_PER_IDENTITY} other calls ` +
              "of this user ran all the time. Make fewer calls at once."
          )
        );
      }, Math.max(0, call.until - Date.now()));
      queue.push(start);
      call.signal?.addEventListener("abort", onAbort, { once: true });
    });
  }

  leaveCall(identity: string): void {
    // The call that waited longest takes over the place.
    const next = this.callsWaiting.get(identity)?.[0];
    if (next) return next();
    const running = (this.callsRunning.get(identity) ?? 1) - 1;
    if (running > 0) this.callsRunning.set(identity, running);
    else this.callsRunning.delete(identity);
    this.callsTotal = Math.max(0, this.callsTotal - 1);
    if (this.callsTotal === 0) this.onIdle?.();
  }

  /**
   * Stop every tool call that is running or starts from now on, for a server that is about to exit. Calls answer at
   * once that the server is restarting instead of being cut off without an answer. A POST or PATCH that is already on
   * its way to F&O gets up to graceMs more for F&O's answer, so its outcome is known instead of open. Once the grace
   * is over it is stopped too and says that F&O may have applied it. Shared loads such as the entity list are left to
   * finish on their own. A server that cannot count its connections, the stdio one, gives onIdle: it is called at once
   * when no tool call runs, otherwise whenever the last running call leaves, which is before that call has answered.
   */
  shutdown(graceMs = 0, onIdle?: () => void): void {
    if (this.stopping) return;
    this.stopController.abort(SHUTDOWN);
    const stopWrites = () => this.stopWritesController.abort(SHUTDOWN);
    if (graceMs > 0) setTimeout(stopWrites, graceMs).unref();
    else stopWrites();
    this.onIdle = onIdle;
    if (this.callsTotal === 0) onIdle?.();
  }

  /** True once shutdown was called. */
  get stopping(): boolean {
    return this.stopController.signal.aborted;
  }

  /** Fires on shutdown. FoClient.withBudget combines it with the cancel signal of each call. */
  get stopSignal(): AbortSignal {
    return this.stopController.signal;
  }

  /** Fires when the grace of shutdown for writes already sent is over, at once without a grace. */
  get stopWritesSignal(): AbortSignal {
    return this.stopWritesController.signal;
  }

  /** Count n more bytes of F&O answers in, or return false when that would pass MAX_BYTES_HELD. */
  holdBytes(n: number): boolean {
    if (this.bytesHeld + n > MAX_BYTES_HELD) return false;
    this.bytesHeld += n;
    return true;
  }

  releaseBytes(n: number): void {
    this.bytesHeld = Math.max(0, this.bytesHeld - n);
  }

  /** The one parsed entity list for an answer with this hash, parsed only when no identity has it yet. */
  shareEntityList(hash: string, parse: () => DataEntity[]): DataEntity[] {
    const known = this.entityLists.get(hash);
    if (known) return known;
    const value = parse();
    // A list that no identity holds any more, after a refresh or after its users went idle, is dropped now.
    const inUse = new Set([...this.caches.values()].map((c) => c.entityCache?.value));
    for (const [key, list] of this.entityLists) if (!inUse.has(list)) this.entityLists.delete(key);
    this.entityLists.set(hash, value);
    return value;
  }

  constructor(readonly config: FoConfig) {
    const foHost = new URL(config.url).hostname;
    const tls: Pick<ConnectionOptions, "ca" | "rejectUnauthorized"> = {};
    if (config.caFile) {
      // Trust exactly this certificate, for example the self-signed one of the LCS VHD one-box.
      let pem: string;
      try {
        pem = readFileSync(config.caFile, "utf8");
      } catch (error) {
        throw new Error(`Cannot read FO_CA_FILE ${config.caFile}: ${(error as Error).message}`);
      }
      if (!pem.includes("-----BEGIN CERTIFICATE-----")) throw new Error(`FO_CA_FILE ${config.caFile} is not a PEM certificate`);
      tls.ca = pem;
    } else if (config.insecureTls) {
      tls.rejectUnauthorized = false;
      console.error(`fo-mcp: certificate validation is disabled for ${foHost} (FO_INSECURE_TLS). Prefer FO_CA_FILE.`);
    }
    const connect: buildConnector.BuildOptions = { ...tls };
    let noProxy: string | undefined;
    if (config.hostIp) {
      // Resolve the F&O host name to a fixed IP, so the one-box works without a hosts file entry.
      // Every other host name, such as a proxy, still goes through normal DNS.
      const ip = config.hostIp;
      const family = isIP(ip);
      const fixed: LookupFunction = (hostname, options, callback) => {
        if (hostname !== foHost) return lookup(hostname, options, callback);
        if (options.all) callback(null, [{ address: ip, family }]);
        else callback(null, ip, family);
      };
      connect.lookup = fixed;
      // A proxy resolves the name itself, which cannot work for the one-box, so reach the F&O host directly.
      noProxy = [process.env.no_proxy ?? process.env.NO_PROXY, foHost].filter(Boolean).join(",");
    }
    // Without a proxy undici connects with `connect`. Behind HTTPS_PROXY it opens a CONNECT tunnel and builds
    // the TLS session to F&O from `requestTls` instead, so the certificate options go in both.
    this.dispatcher = new EnvHttpProxyAgent({ connect, requestTls: tls, noProxy });
  }
}

/** The tool call that is running: its deadline, its cancel signals and the bytes of F&O answers it holds. */
interface CallContext {
  until: number;
  /** Fires when the client cancels the call or the server shuts down. */
  signal?: AbortSignal;
  /** Fires when the client cancels the call or the grace of a shutdown is over. A POST or PATCH that went out listens to this one. */
  writeSignal?: AbortSignal;
  /** Released when the call ends, since the rows it read stay in memory until then. */
  heldBytes: number;
  ended: boolean;
}

/**
 * The context of the tool call that is running, see withBudget. One instance for the process: on Node 22 every
 * AsyncLocalStorage that ever ran stays registered, so one per client would slow every promise.
 */
const deadline = new AsyncLocalStorage<CallContext>();

/** Request a token from Entra. Used for client credentials and for the on-behalf-of exchange. */
async function requestEntraToken(shared: FoShared, form: Record<string, string>): Promise<{ accessToken: string; expiresIn: number }> {
  const url = `${shared.config.authority}/${shared.config.tenantId}/oauth2/v2.0/token`;
  // Its own timeout: the request is shared by concurrent calls (see getToken), each of which waits within its own budget.
  let response: { ok: boolean; status: number; text: string; location: string | null };
  try {
    const r = await fetch(url, {
      method: "POST",
      body: new URLSearchParams(form),
      dispatcher: shared.loginDispatcher,
      // Following a redirect would send the client secret, and the user's token for on-behalf-of, on to the host it names.
      redirect: "manual",
      signal: AbortSignal.timeout(shared.config.timeoutMs),
    });
    response = { ok: r.ok, status: r.status, text: await r.text(), location: r.headers.get("location") };
  } catch (error) {
    const err = error as Error & { cause?: Error & { code?: string } };
    const cause = err.cause ? ` (${[err.cause.code, err.cause.message].filter(Boolean).join(" ")})` : "";
    throw new FoError(`Token request to ${url} failed: ${err.message}${cause}`);
  }
  if (response.status >= 300 && response.status < 400) {
    let host = "an unreadable address";
    try {
      host = new URL(response.location ?? "", url).host;
    } catch {
      // keep the unreadable address
    }
    throw new FoError(`Token request to ${url} was answered with a redirect to ${host}, which is not followed. Check FO_AUTHORITY.`, response.status);
  }
  const json = parseJson<{ access_token?: string; expires_in?: number; error?: string; error_description?: string }>(response.text);
  if (!response.ok || !json?.access_token) {
    const detail = json ? `${json.error ?? ""} ${json.error_description ?? ""}`.trim() : describeBody(response.text);
    throw new FoError(`Token request to ${url} failed with ${response.status}: ${detail}`, response.status);
  }
  return { accessToken: json.access_token, expiresIn: json.expires_in ?? 3600 };
}

/** Client credentials: the server acts as the F&O user mapped to the client ID. */
export function clientCredentialsTokenSource(shared: FoShared): TokenSource {
  const { config } = shared;
  return () =>
    requestEntraToken(shared, {
      grant_type: "client_credentials",
      client_id: config.clientId,
      client_secret: config.clientSecret,
      // The F&O URL is the resource. No API permissions are needed on the app registration,
      // F&O authorises the client ID through System administration > Setup > Microsoft Entra ID applications.
      scope: `${config.url}/.default`,
    });
}

/**
 * On-behalf-of: exchange the token a user presented to the MCP server for an F&O token of that user.
 * F&O then applies the roles of the user, not of a service account.
 */
export function onBehalfOfTokenSource(shared: FoShared, userAssertion: string): TokenSource {
  const { config } = shared;
  return () =>
    requestEntraToken(shared, {
      grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
      client_id: config.clientId,
      client_secret: config.clientSecret,
      assertion: userAssertion,
      requested_token_use: "on_behalf_of",
      scope: `${config.url}/.default`,
    });
}


/**
 * Largest F&O answer read into memory. Results are cut to 40 KB for the model anyway, so a page of /data rows over
 * 4 MB is only memory spent. /Metadata answers are bigger by nature (DataEntities is about 2 MB).
 */
const MAX_DATA_BYTES = 4_000_000;
const MAX_METADATA_BYTES = 20_000_000;

/** Time a retried request needs on top of the Retry-After wait, so a throttled GET is only retried when it can still finish. */
const THROTTLE_MARGIN_MS = 5_000;

/** The note for a write that failed after it went out, in a way that does not prove F&O did nothing. */
const MAY_HAVE_BEEN_APPLIED: Record<WriteKind, string> = {
  create: "F&O may still have processed the request, so check with query_entity before repeating a create.",
  update: "F&O may still have applied the update, read the record before trying again.",
  action: "F&O may still have run the action.",
};

/**
 * Time a POST or PATCH needs left in the budget to be sent at all. A write that starts later would most likely run
 * out of time while F&O processes it, and then nobody knows whether it was applied.
 */
const MIN_WRITE_MS = 5_000;

/** Network errors that happen before a request is sent, so a POST that failed with one of them certainly did nothing. */
const NOT_SENT = /ECONNREFUSED|ENOTFOUND|EAI_AGAIN|EHOSTUNREACH|ENETUNREACH|CONNECT_TIMEOUT|CERT|SELF_SIGNED|UNABLE_TO_VERIFY|ALTNAME/;

/** Longest F&O error text passed on. Infolog messages matter, pages of them do not. */
const MAX_ERROR_CHARS = 1_500;

const EXPAND_EXAMPLE = "expand=SalesOrderLines($select=ItemNumber,OrderedSalesQuantity)";

/**
 * Wait for work that several tool calls share (the token request, the entity list) within the budget and the cancel signal
 * of the calling one. The shared work itself runs outside any call's context, so one call ending never fails the others.
 */
function waitWithin<T>(shared: Promise<T>, what: string | (() => string), timeoutMs: number): Promise<T> {
  const store = deadline.getStore();
  if (!store) return shared;
  if (store.signal?.aborted) return Promise.reject(cancelled(store.signal));
  return new Promise<T>((resolve, reject) => {
    const onAbort = () => reject(cancelled(store.signal));
    const name = () => (typeof what === "function" ? what() : what);
    const timer = setTimeout(() => reject(new FoError(`No answer from ${name()} within the ${timeoutMs / 1000} s a tool call may take.`)), Math.max(0, store.until - Date.now()));
    store.signal?.addEventListener("abort", onAbort, { once: true });
    shared.then(resolve, reject).finally(() => {
      clearTimeout(timer);
      store.signal?.removeEventListener("abort", onAbort);
    });
  });
}

/**
 * The error for a call stopped by the client or by FoShared.shutdown. The signal is passed in rather than read from the
 * call's context, because an abort listener runs in the context of whoever aborted. A write that already went out
 * may have been applied, so its error says so.
 */
function cancelled(signal: AbortSignal | undefined, sentWrite?: WriteKind): FoError {
  const restarting = signal?.reason === SHUTDOWN;
  const message = restarting ? "The server is restarting, so the tool call was stopped." : "The tool call was cancelled.";
  const next = sentWrite ? ` ${MAY_HAVE_BEEN_APPLIED[sentWrite]}` : restarting ? " Call the tool again in a moment." : "";
  return new FoError(message + next, undefined, undefined, sentWrite !== undefined);
}

/** Wait ms milliseconds, or less when the tool call is cancelled meanwhile. */
function pause(ms: number, signal?: AbortSignal): Promise<void> {
  if (signal?.aborted) return Promise.reject(cancelled(signal));
  return new Promise<void>((resolve, reject) => {
    const onAbort = () => {
      clearTimeout(timer);
      reject(cancelled(signal));
    };
    const timer = setTimeout(() => {
      signal?.removeEventListener("abort", onAbort);
      resolve();
    }, ms);
    signal?.addEventListener("abort", onAbort, { once: true });
  });
}

/**
 * Retry-After in milliseconds, given as seconds (a fraction is tolerated) or as an HTTP date. Undefined when it is
 * missing or unreadable. Date.parse reads almost anything, "1.5", "-5" and "soon 5" as days in 2001, so only text that
 * names a month, as every HTTP date format does, is taken as a date.
 */
function parseRetryAfter(value: string | null): number | undefined {
  const text = value?.trim();
  if (!text) return undefined;
  if (/^\d+(\.\d+)?$/.test(text)) return Number(text) * 1000;
  if (!/\b(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\b/i.test(text)) return undefined;
  const at = Date.parse(text);
  return Number.isNaN(at) ? undefined : Math.max(0, at - Date.now());
}

function seconds(ms: number): string {
  const s = Math.max(1, Math.ceil(ms / 1000));
  return `${s} second${s === 1 ? "" : "s"}`;
}

/**
 * Read a response body, but never more than limit bytes into memory. With `shared` the bytes also count against the
 * process wide MAX_BYTES_HELD: a tool call holds them until it ends, work shared between calls only while it reads.
 */
async function readBody(
  response: Awaited<ReturnType<typeof fetch>>,
  shown: string,
  limit: number,
  advice: string,
  shared?: FoShared,
  call?: CallContext
): Promise<string> {
  // With the status of the answer: this is an answer that arrived and was refused here, not a server nobody reached.
  const tooLarge = () => new FoError(`The answer from ${shown} is over ${limit / 1_000_000} MB.${advice}`, response.status);
  if (Number(response.headers.get("content-length") ?? 0) > limit) {
    await response.body?.cancel().catch(() => {});
    throw tooLarge();
  }
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    for await (const chunk of response.body ?? []) {
      if (size + chunk.byteLength > limit) {
        await response.body?.cancel().catch(() => {});
        throw tooLarge();
      }
      if (shared && !shared.holdBytes(chunk.byteLength)) {
        await response.body?.cancel().catch(() => {});
        throw new FoError(
          "The server is busy reading other large F&O answers. Try again in a moment, or pass select with the fields you need and a smaller top."
        );
      }
      size += chunk.byteLength;
      chunks.push(chunk);
    }
  } catch (error) {
    shared?.releaseBytes(size);
    throw error;
  }
  const text = new TextDecoder().decode(Buffer.concat(chunks));
  if (shared) {
    if (call && !call.ended) call.heldBytes += size;
    else shared.releaseBytes(size);
  }
  return text;
}

export class FoClient {
  private token: { value: string; expiresAt: number } | undefined;
  private tokenFetch: Promise<string> | undefined;
  private readonly config: FoConfig;
  private readonly tokenSource: TokenSource;
  private readonly cacheKey: string;

  /**
   * @param shared dispatchers and caches shared by every client of the environment
   * @param tokenSource how this client gets its F&O token, client credentials by default
   * @param userName display name of the signed in user when the client acts on behalf of one
   * @param userKey stable ID of that user, the Entra object ID, which selects the user's own caches
   */
  constructor(
    private readonly shared: FoShared,
    tokenSource?: TokenSource,
    readonly userName?: string,
    userKey?: string
  ) {
    this.config = shared.config;
    this.delegated = tokenSource !== undefined;
    this.tokenSource = tokenSource ?? clientCredentialsTokenSource(shared);
    this.cacheKey = userKey ? `user:${userKey}` : "service";
  }

  /** True when the client acts for a signed in user (on-behalf-of), false for client credentials. */
  private readonly delegated: boolean;

  /** Looked up on every use, so a user's caches stay alive while the user is active. */
  private get cache(): FoCaches {
    return this.shared.cachesFor(this.cacheKey);
  }

  get baseUrl(): string {
    return this.config.url;
  }

  get defaultCompany(): string | undefined {
    return this.config.company;
  }

  get allowWrites(): boolean {
    return this.config.allowWrites;
  }

  /** The F&O identity this client acts as: "service" for client credentials, user:<object ID> for a signed in user. */
  get identity(): string {
    return this.cacheKey;
  }

  /**
   * True once the tool call that is running was cancelled by the client or stopped by a shutdown. A tool that turns a
   * failed part of its answer into a note checks it, so that a stopped call still ends as stopped.
   */
  get callStopped(): boolean {
    return deadline.getStore()?.signal?.aborted ?? false;
  }

  /** The FO_ENTITIES allowlist, empty when every entity is allowed. */
  get allowedEntities(): string[] {
    return this.config.entities;
  }

  /** True when the allowlist is empty or contains this collection. */
  isAllowed(collection: string): boolean {
    return this.config.entities.length === 0 || this.config.entities.some((e) => e.toLowerCase() === collection.toLowerCase());
  }

  /** The FO_WRITE_ENTITIES list, empty when every entity the server may read may also be written. */
  get writeEntities(): string[] {
    return this.config.writeEntities;
  }

  /** True when the write list is empty or contains this collection. */
  isWritable(collection: string): boolean {
    return this.config.writeEntities.length === 0 || this.config.writeEntities.some((e) => e.toLowerCase() === collection.toLowerCase());
  }

  get tlsValidationDisabled(): boolean {
    return this.config.insecureTls && !this.config.caFile;
  }

  // ---------------------------------------------------------------- HTTP

  /**
   * Run one tool call with a time budget of timeoutMs, shared by every request it makes. `signal` is the MCP
   * cancel signal: once the client cancels, or the server shuts down, requests in flight are aborted and no write is
   * sent any more.
   */
  async withBudget<T>(work: () => Promise<T>, signal?: AbortSignal): Promise<T> {
    // Signals for the call that fire on whichever source comes first. Listeners rather than AbortSignal.any, since the
    // shutdown signals live as long as the process and must not collect a dependent signal for every call.
    const detach: Array<() => void> = [];
    const either = (sources: Array<AbortSignal | undefined>): AbortSignal => {
      const stop = new AbortController();
      for (const source of sources) {
        if (!source) continue;
        if (source.aborted) {
          stop.abort(source.reason);
          break;
        }
        const onAbort = () => stop.abort(source.reason);
        source.addEventListener("abort", onAbort, { once: true });
        detach.push(() => source.removeEventListener("abort", onAbort));
      }
      return stop.signal;
    };
    const call: CallContext = {
      until: Date.now() + this.config.timeoutMs,
      signal: either([this.shared.stopSignal, signal]),
      writeSignal: either([this.shared.stopWritesSignal, signal]),
      heldBytes: 0,
      ended: false,
    };
    try {
      return await deadline.run(call, work);
    } finally {
      call.ended = true;
      this.shared.releaseBytes(call.heldBytes);
      for (const undo of detach) undo();
    }
  }

  private async getToken(): Promise<string> {
    if (this.token && this.token.expiresAt > Date.now() + 60_000) return this.token.value;
    // A call that is already cancelled starts nothing new.
    const signal = deadline.getStore()?.signal;
    if (signal?.aborted) throw cancelled(signal);
    // Share one token request between concurrent callers. It runs outside the caller's context, so neither the budget
    // nor a cancel of the call that happened to start it can fail the others.
    if (!this.tokenFetch) {
      this.tokenFetch = deadline
        .exit(() => this.tokenSource())
        .then((t) => {
          this.token = { value: t.accessToken, expiresAt: Date.now() + t.expiresIn * 1000 };
          return t.accessToken;
        })
        .finally(() => {
          this.tokenFetch = undefined;
        });
      // Every caller handles the outcome through waitWithin, but if they all stopped waiting a failure must not go unhandled.
      this.tokenFetch.catch(() => {});
    }
    return waitWithin(this.tokenFetch, "the Entra token endpoint", this.config.timeoutMs);
  }

  /**
   * Send one request and read the whole body within the remaining time budget of the tool call. Redirects are not
   * followed: F&O itself never redirects an API call, and a body must not be sent on to another host. `write` is set
   * for anything but a GET: once such a request went out, a failure without an answer leaves its outcome unknown.
   */
  private async send(
    url: string,
    init: { method: string; headers?: Record<string, string>; body?: string },
    write?: WriteKind,
    onSend?: () => void
  ): Promise<{ ok: boolean; status: number; text: string; headers: { get(name: string): string | null } }> {
    const store = deadline.getStore();
    const remaining = (store?.until ?? Date.now() + this.config.timeoutMs) - Date.now();
    const shown = readableUrl(url);
    const foHost = url.startsWith(this.config.url);
    const unknownOutcome = write && foHost ? ` ${MAY_HAVE_BEEN_APPLIED[write]}` : "";
    const timedOut = (sent: boolean) =>
      new FoError(
        `No answer from ${shown} within the ${this.config.timeoutMs / 1000} s a tool call may take.` +
          (foHost && !write ? " The first call after a restart can be slow, try again." : "") +
          (sent ? unknownOutcome : ""),
        undefined,
        undefined,
        sent && write !== undefined
      );
    // Nothing has gone out yet, so a cancel or a shutdown stops the request here whatever it is.
    if (store?.signal?.aborted) throw cancelled(store.signal);
    if (remaining <= 0) throw timedOut(false);
    const timeout = AbortSignal.timeout(remaining);
    const [limit, advice] = url.startsWith(`${this.config.url}/Metadata/`)
      ? [MAX_METADATA_BYTES, ""]
      : [MAX_DATA_BYTES, ` Pass select with the fields you need, a smaller top, or select inside expand, for example ${EXPAND_EXAMPLE}.`];
    // Once a create or update is on its way, a shutdown waits for F&O's answer within its grace (FoShared.shutdown),
    // so the outcome is known. A read, the version actions included, stops at once.
    const stop = write === "create" || write === "update" ? store?.writeSignal : store?.signal;
    try {
      const signal = stop ? AbortSignal.any([timeout, stop]) : timeout;
      onSend?.();
      const response = await fetch(url, { ...init, redirect: "manual", dispatcher: this.shared.dispatcher, signal });
      // The answer to a write is read whatever else is in memory: F&O has done the write, failing now would hide that.
      const text = await readBody(response, shown, limit, advice, write ? undefined : this.shared, store);
      return { ok: response.ok, status: response.status, text, headers: response.headers };
    } catch (error) {
      if (error instanceof FoError) throw error;
      const err = error as Error & { cause?: Error & { code?: string } };
      if (stop?.aborted) throw cancelled(stop, write);
      if (err.name === "TimeoutError" || timeout.aborted) throw timedOut(true);
      const code = err.cause?.code ?? "";
      const cause = err.cause ? ` (${[code, err.cause.message].filter(Boolean).join(" ")})` : "";
      // These errors come before the request went out. onSend has run already, so notSent tells the caller that F&O got nothing.
      const notSent = NOT_SENT.test(code);
      let hint = "";
      let outcomeUnknown = false;
      if (/CERT|SELF_SIGNED|UNABLE_TO_VERIFY|ALTNAME/.test(code)) {
        hint = " Set FO_CA_FILE to the server certificate, or FO_INSECURE_TLS=1 for a throwaway box.";
      } else if (/ENOTFOUND|EAI_AGAIN/.test(code) && foHost) {
        hint = " Set FO_HOST_IP when the F&O host name does not resolve on this machine.";
      } else if (unknownOutcome && !notSent) {
        // The connection broke after the request went out, F&O may have done the write before it did.
        hint = unknownOutcome;
        outcomeUnknown = true;
      }
      throw new FoError(`Request to ${shown} failed: ${err.message}${cause}${hint}`, undefined, undefined, outcomeUnknown, notSent);
    }
  }

  /**
   * Send one request to the F&O environment and return the text of a successful answer. Retries once with a fresh token
   * on 401, and a GET once more when F&O throttles and the Retry-After wait still fits in the time budget. Anything but
   * a GET is never repeated otherwise, and a create or update is not started at all when too little of the budget is left.
   */
  private async exchange(path: string, init: FoRequestInit, retries: Retries = { unauthorized: true, throttled: true }): Promise<{ text: string; status: number }> {
    if (!path.startsWith("/")) throw new FoError(`Request path must be relative to the F&O URL, got '${path}'`);
    const token = await this.getToken();
    const method = init.method ?? "GET";
    const write = method === "GET" ? undefined : (init.kind ?? (method === "POST" ? "create" : "update"));
    if (write) {
      const store = deadline.getStore();
      // A write must not start after the client cancelled, for example while the metadata or the token was loading.
      if (store?.signal?.aborted) throw cancelled(store.signal);
      // Nor so late that F&O could not answer it within the budget. With a budget under ten seconds half of it is
      // enough, so a short FO_TIMEOUT_MS still allows writes at all. An action only reads and is tried whatever is left.
      const left = store ? store.until - Date.now() : Infinity;
      if (write !== "action" && left < Math.min(MIN_WRITE_MS, this.config.timeoutMs / 2)) {
        throw new FoError(
          `${method} ${readableUrl(path)} was not sent, so nothing changed in F&O: only ${(Math.max(0, left) / 1000).toFixed(1)} s of the ` +
            `${this.config.timeoutMs / 1000} s a tool call may take were left, too little for F&O to answer a write. Try again in a moment.`
        );
      }
    }
    const response = await this.send(
      `${this.config.url}${path}`,
      {
        method,
        headers: {
          Authorization: `Bearer ${token}`,
          Accept: "application/json",
          "User-Agent": `fo-mcp/${version}`,
          ...(init.body !== undefined ? { "Content-Type": "application/json" } : {}),
        },
        body: init.body !== undefined ? JSON.stringify(init.body) : undefined,
      },
      write,
      init.onSend
    );
    if (response.status === 401 && retries.unauthorized) {
      // F&O rejected the token before any business logic ran, so even a POST or PATCH is safe to repeat once.
      if (this.token?.value === token) this.token = undefined;
      return this.exchange(path, init, { ...retries, unauthorized: false });
    }
    if (response.status >= 300 && response.status < 400) {
      let host = "an unknown location";
      try {
        host = new URL(response.headers.get("location") ?? "", this.config.url).host || host;
      } catch {
        // keep the unknown location
      }
      throw new FoError(`F&O answered ${method} ${readableUrl(path)} with a redirect to ${host}. FO_URL is probably not the environment URL.`, response.status);
    }
    const throttled = response.status === 429 || response.status === 503;
    const retryAfterMs = throttled ? parseRetryAfter(response.headers.get("retry-after")) : undefined;
    if (method === "GET" && retries.throttled && retryAfterMs !== undefined) {
      // Reading is safe to repeat. A write is not: the caller decides with the user whether to send it again.
      const store = deadline.getStore();
      const left = (store?.until ?? Date.now() + this.config.timeoutMs) - Date.now();
      if (retryAfterMs + THROTTLE_MARGIN_MS <= left) {
        await pause(retryAfterMs, store?.signal);
        return this.exchange(path, init, { ...retries, throttled: false });
      }
    }
    if (!response.ok) {
      let detail = extractError(response.text);
      if (response.status === 401) {
        detail = this.delegated
          ? `F&O rejected the token of ${this.userName ?? "the signed in user"}. Check that FO_URL is the environment URL, ` +
            `that the environment signs users in with the same Entra tenant and that the app registration has the ` +
            `Dynamics ERP delegated permissions with admin consent.`
          : `F&O rejected the access token. Check that client ID ${this.config.clientId} is listed under ` +
            `System administration > Setup > Microsoft Entra ID applications and mapped to an enabled user.`;
      } else if (response.status === 429) {
        detail += ` F&O is throttling requests${retryAfterMs !== undefined ? `, retry after ${seconds(retryAfterMs)}` : ""}.`;
      } else if (retryAfterMs !== undefined) {
        detail += ` Retry after ${seconds(retryAfterMs)}.`;
      }
      // A gateway error says nothing about whether F&O got to the request behind it.
      const outcomeUnknown = write !== undefined && [502, 503, 504].includes(response.status);
      if (write && outcomeUnknown) detail += ` ${MAY_HAVE_BEEN_APPLIED[write]}`;
      throw new FoError(`${method} ${readableUrl(path)} failed with ${response.status}: ${detail}`, response.status, undefined, outcomeUnknown);
    }
    return { text: response.text, status: response.status };
  }

  /**
   * Call the F&O environment. `path` starts with /data or /Metadata. See exchange for retries and for when a write is
   * not sent. Resolves to undefined when a POST or PATCH comes back with an empty body (204 after an update, actions
   * that return nothing). A GET always resolves to parsed JSON or throws.
   */
  async request<T>(path: string, init: FoRequestInit = {}): Promise<T> {
    const method = init.method ?? "GET";
    const { text, status } = await this.exchange(path, init);
    if (!text && method !== "GET") return undefined as T;
    return parseAnswer<T>(text, `${method} ${readableUrl(path)}`, status);
  }

  /** GET a collection. F&O wraps the rows in { value: [...] }, anything else means the URL or a proxy is wrong. */
  async requestCollection<T>(path: string): Promise<{ value: T[]; "@odata.count"?: number }> {
    return asCollection<T>(await this.request<unknown>(path), path);
  }

  /**
   * Call an action bound to an entity collection, for example GetApplicationVersion on DataManagementEntities. Only for
   * actions that read: it is sent however little of the budget is left, see WriteKind.
   */
  async callBoundAction<T>(entitySet: string, action: string, body: Record<string, unknown> = {}): Promise<T> {
    return this.request<T>(`/data/${entitySet}/${DATA_ENTITIES_NAMESPACE}${action}`, { method: "POST", body, kind: "action" });
  }

  // ---------------------------------------------------------------- Metadata

  /** All data entities. Cached for ten minutes, so entities deployed during a session show up without a restart. */
  async listEntities(): Promise<DataEntity[]> {
    const cache = this.cache;
    if (cache.entityCache) {
      const now = Date.now();
      const fresh = now - cache.entityCache.fetchedAt < METADATA_CACHE_TTL_MS;
      const backingOff = now - cache.entityRefreshFailedAt < RETRY_AFTER_MS;
      if (fresh || backingOff) return cache.entityCache.value;
    }
    // An answer that arrived and was no list fails the call, and the next calls with it for RETRY_AFTER_MS: asking
    // again at once would download an answer over the size limit in full every time.
    if (cache.entityRefusal && Date.now() - cache.entityRefusal.at < RETRY_AFTER_MS) throw cache.entityRefusal.error;
    const signal = deadline.getStore()?.signal;
    if (signal?.aborted) throw cancelled(signal);
    const load = this.loadEntities(cache);
    // The load starts with the token request, so name whichever of the two is still outstanding when time runs out.
    const waitingFor = () => (this.tokenFetch ? "the Entra token endpoint" : readableUrl(`${this.config.url}/Metadata/DataEntities`));
    return waitWithin(load, waitingFor, this.config.timeoutMs);
  }

  /**
   * The load of the entity list that every concurrent call of this identity shares, started here when none runs. It
   * runs outside the calling one's budget and cancel signal. A refresh that fails because F&O was unreachable or busy
   * keeps the old list and F&O is asked again after RETRY_AFTER_MS. Any other failure is the caller's: a 401 or 403
   * says that this identity may not read F&O any more, and the old list would hide that for as long as it keeps calling.
   */
  private loadEntities(cache: FoCaches): Promise<DataEntity[]> {
    const startsHere = !cache.entityFetch;
    const path = "/Metadata/DataEntities";
    cache.entityFetch ??= deadline
      .exit(() => this.exchange(path, {}))
      .then(({ text, status }) => {
        // Users usually get the same answer, and then they share the one parsed list instead of a copy each.
        const hash = createHash("sha256").update(text).digest("base64url");
        const value = this.shared.shareEntityList(hash, () => asCollection<DataEntity>(parseAnswer<unknown>(text, `GET ${path}`, status), path).value);
        cache.entityCache = { value, fetchedAt: Date.now() };
        cache.entityRefusal = undefined;
        return value;
      })
      .catch((error: unknown) => {
        const old = cache.entityCache;
        // A 401 or 403 is asked for again on the next call, it costs F&O nothing and ends when the access is back.
        if (error instanceof FoError && error.status !== undefined && error.status < 300) cache.entityRefusal = { error, at: Date.now() };
        if (!old || !unavailable(error)) throw error;
        cache.entityRefreshFailedAt = Date.now();
        // One line per failed refresh, so an operator sees when F&O stays unreachable and the list stays old.
        console.error(
          `fo-mcp: the entity list of ${this.userName ?? this.identity} could not be refreshed, the list read at ${new Date(old.fetchedAt).toISOString()} stays in use: ${(error as Error).message}`
        );
        return old.value;
      })
      .finally(() => {
        cache.entityFetch = undefined;
      });
    // As with the token request: nobody may be left waiting, a failure must still be handled.
    if (startsHere) cache.entityFetch.catch(() => {});
    return cache.entityFetch;
  }

  /** Map a collection name, public entity name or entity name to the OData collection name. */
  async resolveEntitySet(name: string): Promise<string> {
    const cache = this.cache;
    const wanted = name.trim().toLowerCase();
    if (!wanted) throw new FoError("Entity name is empty. Use search_entities to find the collection name.");
    const entities = await this.listEntities();
    const match =
      entities.find((e) => e.PublicCollectionName.toLowerCase() === wanted) ??
      entities.find((e) => e.PublicEntityName.toLowerCase() === wanted) ??
      entities.find((e) => e.Name.toLowerCase() === wanted);
    if (!match) {
      // It may have been deployed after the list was cached. The miss is still answered from that list at once, and the
      // list is refreshed behind the answer, at most once every MISS_REFRESH_MS and not while a failed refresh backs
      // off, so the next call sees the entity. Nobody waits for the load, it is shared with the calls that do, see loadEntities.
      const now = Date.now();
      const list = cache.entityCache;
      const due = list !== undefined && now - list.fetchedAt > MISS_REFRESH_MS && now - cache.entityMissRefreshAt >= MISS_REFRESH_MS;
      if (due && now - cache.entityRefreshFailedAt >= RETRY_AFTER_MS) {
        // The time of the attempt spaces the next one, not its success: a refresh F&O refuses, with a 401 or 403 for an
        // identity that lost its access, leaves the list as old as it was and would otherwise start again on every guess.
        cache.entityMissRefreshAt = now;
        // Nobody waits for this load, so nobody else would see why it was refused.
        void this.loadEntities(cache).catch((error: unknown) => {
          console.error(`fo-mcp: the entity list of ${this.userName ?? this.identity} was not refreshed after a name it does not have: ${(error as Error).message}`);
        });
      }
      // Suggest only what this server may use, an entity outside FO_ENTITIES would just fail on the next call.
      const similar = suggestEntities(name, entities.filter((e) => this.isAllowed(e.PublicCollectionName)));
      const hint = similar.length ? ` Did you mean ${similar.join(", ")}?` : "";
      throw new FoError(`Entity '${name}' not found.${hint} Use search_entities to look further.`);
    }
    if (!match.DataServiceEnabled) throw new FoError(`Entity '${match.Name}' is not enabled for OData.`);
    if (!this.isAllowed(match.PublicCollectionName)) {
      throw new FoError(`${match.PublicCollectionName} is not on the FO_ENTITIES allowlist of this server. Allowed: ${this.config.entities.join(", ")}.`);
    }
    return match.PublicCollectionName;
  }

  /** Fields, keys and navigation properties of one entity, by collection name. Cached for ten minutes. */
  async getPublicEntity(collection: string): Promise<PublicEntity | undefined> {
    const entities = this.cache.publicEntityCache;
    const cached = recall(entities, collection);
    if (cached) return cached.value;
    const filter = `EntitySetName eq '${escapeODataString(collection)}'`;
    const result = await this.requestCollection<PublicEntity>(`/Metadata/PublicEntities?$filter=${encodeURIComponent(filter)}`);
    const entity = result.value[0];
    if (entity) remember(entities, collection, { value: entity, fetchedAt: Date.now() }, MAX_PUBLIC_ENTITIES);
    return entity;
  }

  /** Resolve an entity from any of its names and load its metadata. */
  async getEntity(name: string): Promise<EntityInfo> {
    const collection = await this.resolveEntitySet(name);
    const details = await this.getPublicEntity(collection);
    if (!details) throw new FoError(`No public metadata found for ${collection}.`);
    return { collection, details, companySpecific: details.Properties.some((p) => p.Name === "dataAreaId") };
  }

  /** Legal entities of the environment, cached for ten minutes. */
  async listCompanies(): Promise<Array<{ id: string; name: string }>> {
    const cache = this.cache;
    if (cache.companyCache && Date.now() - cache.companyCache.fetchedAt < METADATA_CACHE_TTL_MS) return cache.companyCache.value;
    const result = await this.requestCollection<{ LegalEntityId: string; Name: string }>(
      "/data/LegalEntities?$select=LegalEntityId,Name&$orderby=LegalEntityId"
    );
    const companies = result.value.map((e) => ({ id: e.LegalEntityId, name: e.Name }));
    cache.companyCache = { value: companies, fetchedAt: Date.now() };
    return companies;
  }

  /** Resolve a label id such as @SYS16445 to its text. Returns the id unchanged when F&O has no text for it. */
  async getLabel(labelId: string): Promise<string> {
    if (!labelId || !labelId.startsWith("@")) return labelId;
    const key = `${this.config.language}|${labelId}`;
    const cached = recall(this.shared.labelCache, key);
    if (cached) return cached.value;
    let value = labelId;
    try {
      const result = await this.request<{ Value?: string }>(
        `/Metadata/Labels(Id='${encodeURIComponent(escapeODataString(labelId))}',Language='${encodeURIComponent(this.config.language)}')`
      );
      value = result?.Value ?? labelId;
    } catch (error) {
      // 404 is a definite answer. Anything else may be transient, so report it and try again next time.
      if (!(error instanceof FoError && error.status === 404)) throw error;
    }
    remember(this.shared.labelCache, key, { value, fetchedAt: Date.now() }, MAX_SHARED_ENTRIES);
    return value;
  }

  /**
   * Resolve many labels. The Metadata service only answers one label per request, so this runs a few in
   * parallel. Labels that could not be fetched stay as ids and the first error is returned as a problem.
   */
  async getLabels(labelIds: string[], concurrency = 12): Promise<{ labels: Map<string, string>; problem?: string }> {
    const labels = new Map<string, string>();
    let problem: string | undefined;
    await forEachLimited(labelIds.filter((id) => id && id.startsWith("@")), concurrency, async (id) => {
      try {
        labels.set(id, await this.getLabel(id));
      } catch (error) {
        // A cancelled call is not a missing label: it must end as cancelled, not as a description with a warning.
        if (deadline.getStore()?.signal?.aborted) throw error;
        problem ??= `Labels could not be loaded: ${(error as Error).message}`;
        labels.set(id, id);
      }
    });
    return { labels, problem };
  }

  /** The elements of an X++ enum such as NoYes, or undefined when F&O has no public enumeration of that name. */
  async getEnumeration(typeName: string): Promise<PublicEnumeration | undefined> {
    const name = typeName.slice(typeName.lastIndexOf(".") + 1);
    const cached = recall(this.shared.enumCache, name);
    if (cached) return cached.value;
    let value: PublicEnumeration | undefined;
    try {
      const result = await this.request<PublicEnumeration>(`/Metadata/PublicEnumerations('${encodeURIComponent(escapeODataString(name))}')`);
      value = Array.isArray(result?.Members) ? result : undefined;
    } catch (error) {
      // As with labels: 404 is a definite answer, anything else is reported and asked again next time.
      if (!(error instanceof FoError && error.status === 404)) throw error;
    }
    remember(this.shared.enumCache, name, { value, fetchedAt: Date.now() }, MAX_SHARED_ENTRIES);
    return value;
  }

  /** Load several enums in parallel. Enums that could not be loaded are left out and the first error is returned as a problem. */
  async getEnumerations(typeNames: string[], concurrency = 4): Promise<{ enums: Map<string, PublicEnumeration>; problem?: string }> {
    const enums = new Map<string, PublicEnumeration>();
    let problem: string | undefined;
    await forEachLimited(typeNames.filter(Boolean), concurrency, async (typeName) => {
      try {
        const enumeration = await this.getEnumeration(typeName);
        if (enumeration) enums.set(typeName, enumeration);
      } catch (error) {
        if (deadline.getStore()?.signal?.aborted) throw error;
        problem ??= `Enum values could not be loaded: ${(error as Error).message}`;
      }
    });
    return { enums, problem };
  }

  // ---------------------------------------------------------------- OData helpers

  buildQueryUrl(entitySet: string, options: QueryOptions): string {
    const params = new URLSearchParams();
    if (options.filter) params.set("$filter", options.filter);
    if (options.select) params.set("$select", options.select);
    if (options.orderby) params.set("$orderby", options.orderby);
    if (options.expand) params.set("$expand", options.expand);
    if (options.top !== undefined) params.set("$top", String(options.top));
    if (options.skip !== undefined) params.set("$skip", String(options.skip));
    if (options.count) params.set("$count", "true");
    if (options.crossCompany) params.set("cross-company", "true");
    const query = params.toString();
    return `/data/${entitySet}${query ? `?${query}` : ""}`;
  }
}

/**
 * Collection names that share most words with a name the model guessed, for example
 * CustomerPaymentTerms -> PaymentTerms. Words are taken from the camel case name, plurals dropped.
 */
export function suggestEntities(guess: string, entities: DataEntity[], max = 3): string[] {
  const words = guess
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter((w) => w.length > 2)
    .map((w) => w.replace(/(ie)?s$/, (m) => (m === "ies" ? "y" : "")));
  if (!words.length) return [];
  const scored = entities
    .filter((e) => e.DataServiceEnabled && e.PublicCollectionName)
    .map((e) => {
      const haystack = `${e.Name} ${e.PublicEntityName} ${e.PublicCollectionName}`.toLowerCase();
      return { name: e.PublicCollectionName, score: words.filter((w) => haystack.includes(w)).length };
    })
    .filter((x) => x.score >= Math.max(1, words.length - 1))
    .sort((a, b) => b.score - a.score || a.name.length - b.name.length);
  return [...new Set(scored.map((x) => x.name))].slice(0, max);
}

/**
 * A hit in a cache kept in order of use: the entry when it is there and fresh, moved to the end. A Map keeps the order
 * of insertion, so the least recently used entry stays first.
 */
function recall<T>(cache: Map<string, Cached<T>>, key: string): Cached<T> | undefined {
  const entry = cache.get(key);
  if (!entry || Date.now() - entry.fetchedAt >= METADATA_CACHE_TTL_MS) return undefined;
  cache.delete(key);
  cache.set(key, entry);
  return entry;
}

/** Put an entry at the end of such a cache and drop the least recently used ones past max. */
function remember<T>(cache: Map<string, Cached<T>>, key: string, entry: Cached<T>, max: number): void {
  cache.delete(key);
  cache.set(key, entry);
  for (const oldest of cache.keys()) {
    if (cache.size <= max) break;
    cache.delete(oldest);
  }
}

/**
 * True when an error says that nobody answered, or that F&O or this server was busy, and not that the request was
 * refused: the connection or the token request failed, no answer came within the budget, F&O throttles or answers
 * 5xx, or this server holds too many answers. A refresh of a cached list that fails this way keeps the old list.
 */
function unavailable(error: unknown): boolean {
  if (!(error instanceof FoError)) return false;
  // Without a status no answer was read. An answer that arrived and was refused here, one over the size limit or one
  // without rows, carries the status it came with and fails the call like any other answer.
  if (error.status === undefined) return true;
  return error.status === 429 || error.status >= 500;
}

/** Run fn for every distinct item, at most `concurrency` at a time. */
async function forEachLimited<T>(items: T[], concurrency: number, fn: (item: T) => Promise<void>): Promise<void> {
  const unique = [...new Set(items)];
  let next = 0;
  const worker = async () => {
    while (next < unique.length) await fn(unique[next++]);
  };
  await Promise.all(Array.from({ length: Math.min(concurrency, unique.length) }, worker));
}

/** A URL as a human would write it, with the percent encoding undone. */
export function readableUrl(url: string): string {
  try {
    return decodeURIComponent(url.replace(/\+/g, " "));
  } catch {
    return url;
  }
}

/** Double single quotes, the OData way of escaping a quote inside a string literal. */
export function escapeODataString(value: string): string {
  return value.replace(/'/g, "''");
}

/** The Metadata service reports the X++ enum name (NoYes), OData literals need the qualified name. */
export function qualifyEnum(typeName: string): string {
  return typeName.includes(".") ? typeName : `${DATA_ENTITIES_NAMESPACE}${typeName}`;
}

/**
 * What a key literal may look like, by Metadata DataType. Anything else is refused with a clear message
 * instead of being sent to F&O, which answers "No HTTP resource was found" for a malformed literal.
 * Time keys are seconds since midnight.
 */
const DATE_LITERAL = /^\d{4}-\d{2}-\d{2}(T\d{2}:\d{2}(:\d{2}(\.\d+)?)?(Z|[+-]\d{2}:\d{2}))?$/;
const KEY_LITERALS: Record<string, RegExp> = {
  Int32: /^-?\d+$/,
  Int64: /^-?\d+$/,
  Time: /^-?\d+$/,
  Real: /^-?\d+(\.\d+)?([eE][+-]?\d+)?$/,
  Guid: /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i,
  Date: DATE_LITERAL,
  UtcDateTime: DATE_LITERAL,
};

/**
 * Build the key segment of an entity URL, for example (dataAreaId='usmf',CustomerAccount='US-001').
 * Literals follow the field type: strings and enums are quoted, numbers, dates and GUIDs are bare.
 * Values are percent encoded so characters such as # ? and % cannot change the URL. A slash or backslash is
 * still fatal: F&O's web server decodes it and routes on the result, so a record whose string key contains
 * one cannot be addressed by URL at all (query_entity with $filter still finds it). Such keys and key types
 * without a known literal form are refused here instead of answering with a confusing routing error.
 */
export function formatKey(keyProperties: EntityProperty[], key: Record<string, unknown>): string {
  const parts = keyProperties.map((prop) => {
    const value = key[prop.Name];
    if (value === undefined || value === null) throw new FoError(`Key field ${prop.Name} is missing`);
    if (typeof value === "object") throw new FoError(`Key field ${prop.Name} must be a string, number or boolean`);
    const text = String(value);
    if (prop.DataType === "String") {
      if (/[\\/]/.test(text)) {
        throw new FoError(
          `Key field ${prop.Name} contains a slash or backslash, which F&O cannot route in a URL, so this record cannot be addressed by its key. ` +
            "query_entity with $filter still finds it."
        );
      }
      return `${prop.Name}='${encodeURIComponent(escapeODataString(text))}'`;
    }
    if (prop.DataType === "Enum") {
      // true and false stand for Yes and No of a NoYes enum, as they do in the expected values of update_record. For any
      // other enum they name no element, and F&O would answer as if the record did not exist.
      if (typeof value === "boolean") {
        if (!/^NoYes/i.test(prop.TypeName.slice(prop.TypeName.lastIndexOf(".") + 1))) {
          throw new FoError(`Key field ${prop.Name} is an enum of type ${prop.TypeName}, which takes an element name, not ${value}. Use the values from describe_entity.`);
        }
        return `${prop.Name}=${qualifyEnum(prop.TypeName)}'${value ? "Yes" : "No"}'`;
      }
      // The plain element name, or the qualified filter form Namespace.Type'Element' that enumType suggests, cut to its element.
      const element = /^[\w.]+'(\w+)'$/.exec(text)?.[1] ?? text;
      if (!/^\w+$/.test(element)) throw new FoError(`Key field ${prop.Name} of type Enum cannot be '${text}'. Pass the plain element name, for example No.`);
      return `${prop.Name}=${qualifyEnum(prop.TypeName)}'${element}'`;
    }
    const allowed = KEY_LITERALS[prop.DataType];
    if (!allowed) {
      throw new FoError(`Key field ${prop.Name} has type ${prop.DataType}, which cannot be written as a key in a URL. Find the record with query_entity and $filter instead.`);
    }
    if (!allowed.test(text)) throw new FoError(`Key field ${prop.Name} of type ${prop.DataType} cannot be '${text}'`);
    return `${prop.Name}=${encodeURIComponent(text)}`;
  });
  return `(${parts.join(",")})`;
}

/** The JSON of a successful answer, or an error that names the request when it is not JSON. */
function parseAnswer<T>(text: string, request: string, status: number): T {
  const json = parseJson<T>(text);
  if (json === undefined) throw new FoError(`${request} returned something that is not JSON: ${describeBody(text)}`, status);
  return json;
}

/** F&O wraps the rows of a collection in { value: [...] }, anything else means the URL or a proxy is wrong. */
function asCollection<T>(result: unknown, path: string): { value: T[]; "@odata.count"?: number } {
  if (!Array.isArray((result as { value?: unknown } | undefined)?.value)) {
    // 200: the answer arrived and parsed, so this is no outage that an old list could cover, see unavailable.
    throw new FoError(`GET ${readableUrl(path)} returned no value array: ${describeBody(JSON.stringify(result ?? ""))}`, 200);
  }
  return result as { value: T[]; "@odata.count"?: number };
}

function parseJson<T>(text: string): T | undefined {
  try {
    return JSON.parse(text) as T;
  } catch {
    return undefined;
  }
}

/** A short, readable description of a response body that is not the JSON we expected. */
function describeBody(text: string): string {
  if (!text) return "(empty response)";
  if (/^\s*<(!doctype|html)/i.test(text)) {
    const title = /<title>([^<]*)<\/title>/i.exec(text)?.[1]?.trim();
    return title ? `HTML page "${title}"` : "HTML page";
  }
  return text.replace(/\s+/g, " ").slice(0, 300);
}

/**
 * Pull the message out of an F&O OData error body: the message, the inner message and the message of the internal
 * exception, where F&O puts the infolog of a failed write. Parts that repeat another are dropped, stack traces never
 * passed on.
 */
function extractError(text: string): string {
  const json = parseJson<{
    error?: { message?: unknown; innererror?: { message?: unknown; internalexception?: { message?: unknown } } };
    Message?: unknown;
    ExceptionMessage?: unknown;
  }>(text);
  let parts: unknown[];
  // F&O answers security and routing errors in the Web API shape { Message, ExceptionMessage } instead of OData's { error }.
  if (!json?.error && typeof json?.Message === "string") parts = [json.Message, json.ExceptionMessage];
  else if (json?.error) parts = [json.error.message, json.error.innererror?.message, json.error.innererror?.internalexception?.message];
  else return describeBody(text);
  const texts = parts.filter((p): p is string => typeof p === "string").map((p) => p.trim()).filter(Boolean);
  const kept = texts.filter((p, i) => !texts.some((q, j) => j !== i && (q === p ? j < i : q.includes(p))));
  if (!kept.length) return describeBody(text);
  const message = kept.join(" | ");
  return message.length > MAX_ERROR_CHARS ? `${message.slice(0, MAX_ERROR_CHARS)} ...` : message;
}
