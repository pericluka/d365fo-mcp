// What the suite does on a machine that cannot run all of it. Without openssl the suites that make certificates are
// skipped with the reason instead of failing in their before hook, on Windows the tests of a graceful shutdown on
// SIGTERM are skipped, and the evals stop the CLI with taskkill instead of a process group. This file needs neither
// openssl nor signals itself. Run with: node --test test/platform.test.mjs
import assert from "node:assert/strict";
import { execFile, spawn } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";
import { noSignals, projectDir, sleep, stopProcessTree, SUITE_TIMEOUT } from "./support.mjs";

describe("the tests and the evals on a machine without openssl or POSIX signals", { timeout: SUITE_TIMEOUT }, () => {
  it("skips the suites that need openssl with the reason when it is not on the PATH, instead of failing them", async () => {
    const empty = mkdtempSync(join(tmpdir(), "fo-mcp-no-openssl-"));
    // The variables node --test sets for its own children would make the nested run report to this one.
    const env = { ...Object.fromEntries(Object.entries(process.env).filter(([name]) => !name.startsWith("NODE_TEST"))), PATH: empty };
    try {
      const { code, output } = await new Promise((resolve) => {
        execFile(process.execPath, ["--test", "--test-reporter=tap", join(projectDir, "test/tools.test.mjs")], { cwd: projectDir, env, timeout: 50_000 }, (error, stdout, stderr) =>
          resolve({ code: error ? (error.code ?? error.signal) : 0, output: `${stdout}${stderr}` })
        );
      });
      assert.equal(code, 0, output);
      assert.match(output, /# SKIP openssl is not on the PATH, and the fake cloud needs it for its test certificate\./);
      assert.match(output, /^# fail 0$/m, output);
    } finally {
      rmSync(empty, { recursive: true, force: true });
    }
  });

  it("skips the tests of a graceful shutdown on Windows, where kill() ends the process at once", () => {
    assert.match(noSignals("win32"), /^Windows has no POSIX signals, kill\(\) ends the process at once/);
    for (const platform of ["darwin", "linux"]) assert.equal(noSignals(platform), false, platform);
  });

  it("stops the eval CLI and the server it started with taskkill /T on Windows, which has no process groups", () => {
    const seen = [];
    const child = { pid: 4242, kill: (signal) => seen.push(["kill", signal]) };
    const taskkill = (result) => (command, args) => (seen.push([command, ...args]), result);
    stopProcessTree(child, "SIGTERM", { platform: "win32", run: taskkill({ status: 0 }) });
    assert.deepEqual(seen, [["taskkill", "/pid", "4242", "/T", "/F"]]);
    // Without taskkill, or when it fails, the CLI itself is still ended.
    seen.length = 0;
    stopProcessTree(child, "SIGKILL", { platform: "win32", run: taskkill({ error: new Error("spawnSync taskkill ENOENT") }) });
    stopProcessTree(child, "SIGKILL", { platform: "win32", run: taskkill({ status: 128 }) });
    assert.deepEqual(seen, [["taskkill", "/pid", "4242", "/T", "/F"], ["kill", "SIGKILL"], ["taskkill", "/pid", "4242", "/T", "/F"], ["kill", "SIGKILL"]]);
  });

  it("stops a detached process and the one it started through its process group elsewhere", { skip: process.platform === "win32" && "Windows has no process groups" }, async () => {
    const script = "const c = require('node:child_process').spawn(process.execPath, ['-e', 'setInterval(() => {}, 1000)'], { stdio: 'ignore' }); console.log(c.pid); setInterval(() => {}, 1000);";
    const child = spawn(process.execPath, ["-e", script], { stdio: ["ignore", "pipe", "ignore"], detached: true });
    const exited = new Promise((resolve) => child.once("exit", resolve));
    const started = Number(await new Promise((resolve) => child.stdout.once("data", (chunk) => resolve(String(chunk).trim()))));
    const alive = (pid) => {
      try {
        process.kill(pid, 0);
        return true;
      } catch {
        return false;
      }
    };
    assert.ok(alive(started), "the process the child started runs");
    stopProcessTree(child);
    await exited;
    for (const until = Date.now() + 5000; alive(started) && Date.now() < until; ) await sleep(20);
    assert.equal(alive(started), false, "the process the child started has ended too");
    // A second stop of what has already exited does not throw.
    stopProcessTree(child, "SIGKILL");
  });
});
