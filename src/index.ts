#!/usr/bin/env node
// Local server: Claude starts this process and talks to it over stdio. Every call runs as the
// F&O user mapped to the client ID (client credentials). For a server that signs users in, see http.ts.
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { insecureTlsWarning, loadProjectEnv, projectDir, version } from "./config.js";
import { FoClient, FoShared, loadConfig } from "./fo.js";
import { createFoServer } from "./server.js";

loadProjectEnv();

// Checked after .env is loaded, since Node reads the variable on every TLS connection and a value from .env counts too.
const tlsWarning = insecureTlsWarning();
if (tlsWarning) console.error(tlsWarning);

let shared: FoShared;
try {
  shared = new FoShared(loadConfig(process.env, projectDir));
} catch (error) {
  console.error(`fo-mcp: ${(error as Error).message}`);
  process.exit(1);
}

if (shared.config.allowWrites && !shared.config.writeEntities.length) {
  console.error(
    "fo-mcp: writes are enabled for every entity the F&O user may change. Set FO_WRITE_ENTITIES to the collections create_record and update_record may use."
  );
}

const fo = new FoClient(shared);
const server = createFoServer({ version, shared, resolve: () => fo });

/**
 * How long a create or update already sent to F&O may wait for its answer after SIGTERM. Shorter than the 20 seconds
 * of http.ts on purpose: a client built on the MCP SDK sends SIGKILL two seconds after SIGTERM, and a write still
 * waiting then dies without an answer and without its audit line. Within this grace the answer and the audit line
 * are out before that, with F&O's result when it came in time and with the outcome left open otherwise.
 */
const WRITE_GRACE_MS = 1_500;

async function main(): Promise<void> {
  // A client that is gone already closes the pipe, and the last answer written after it would otherwise end the
  // process with an uncaught EPIPE. The audit line is on stderr and out by then, so the answer can be dropped.
  process.stdout.on("error", (error: NodeJS.ErrnoException) => {
    if (error.code !== "EPIPE") throw error;
  });
  await server.connect(new StdioServerTransport());
  console.error(`fo-mcp ${version} ready for ${fo.baseUrl}${fo.allowWrites ? " (writes enabled)" : " (read-only)"}`);
  // The MCP client ends stdin when it is done and the process exits by itself once it has nothing left to do. While a
  // tool call still waits for F&O it has, so the client sends SIGTERM two seconds later, and without a handler Node
  // ends the process at once: a create or update that F&O has already applied answers nothing and leaves no audit
  // line. On a signal stop the calls in flight the way the remote server does, see http.ts: reads answer at once that
  // the server is restarting, a create or update already sent gets WRITE_GRACE_MS for F&O's answer. The transport is
  // closed once the last call has left, from the next turn of the event loop, since the answer and the audit line of
  // that call follow in this one and the SDK drops the answer of a call whose transport is closed. Closing pauses stdin,
  // so the process exits by itself once the answers are out, or after the grace while a shared load still runs.
  let closing = false;
  const stop = () => {
    if (shared.stopping) return;
    shared.shutdown(WRITE_GRACE_MS, () => {
      if (closing) return;
      closing = true;
      setImmediate(() => void server.close());
    });
    setTimeout(() => process.exit(0), WRITE_GRACE_MS + 5_000).unref();
  };
  for (const signal of ["SIGTERM", "SIGINT"] as const) process.on(signal, stop);
}

main().catch((error: unknown) => {
  console.error(`fo-mcp: ${(error as Error).message}`);
  process.exit(1);
});
