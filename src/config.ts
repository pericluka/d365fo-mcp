import { existsSync, readFileSync } from "node:fs";
import { dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { parseEnv } from "node:util";

/** Project folder, the one with package.json and .env. */
export const projectDir = dirname(fileURLToPath(new URL("../package.json", import.meta.url)));

/** Version from package.json, reported to MCP clients. */
export const version = (JSON.parse(readFileSync(`${projectDir}/package.json`, "utf8")) as { version: string }).version;

/**
 * Load .env from the project folder into process.env. Like process.loadEnvFile, but tolerant of the UTF-8
 * byte order mark (U+FEFF) that Windows editors often write. Variables already set win.
 */
export function loadProjectEnv(): void {
  const envFile = `${projectDir}/.env`;
  if (!existsSync(envFile)) return;
  const parsed = parseEnv(readFileSync(envFile, "utf8").replace(/^﻿/, ""));
  const caFromEnvironment = process.env.NODE_EXTRA_CA_CERTS !== undefined;
  for (const [name, value] of Object.entries(parsed)) process.env[name] ??= value;
  if (parsed.NODE_EXTRA_CA_CERTS && !caFromEnvironment) {
    // Node reads it only when the process starts, so a value that only exists in .env changes nothing.
    console.error("fo-mcp: NODE_EXTRA_CA_CERTS in .env has no effect, set it in the environment that starts the server.");
  }
}

/**
 * The warning for NODE_TLS_REJECT_UNAUTHORIZED=0, set in the environment or in .env, or undefined when it is not set.
 * It turns off certificate checks for every host, Entra included, not only for the F&O one-box it is usually meant for.
 */
export function insecureTlsWarning(env: NodeJS.ProcessEnv = process.env): string | undefined {
  if (env.NODE_TLS_REJECT_UNAUTHORIZED?.trim() !== "0") return undefined;
  return (
    "fo-mcp: NODE_TLS_REJECT_UNAUTHORIZED=0 turns off certificate validation for every connection, Entra included. " +
    "Remove it and set FO_CA_FILE, or FO_INSECURE_TLS=1 for the F&O host alone."
  );
}
