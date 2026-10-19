/**
 * Smoke test for the NEXUS-Q TypeScript SDK.
 *
 * Run from the repository root after `npm run build` inside
 * bindings/typescript:
 *
 *   NEXUSQ_LIBRARY=target/debug/libnexusq.so node bindings/typescript/dist/smoke.js
 */
import { mkdtempSync, existsSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Vault, version } from "./index";

function fail(message: string): never {
  console.error(message);
  process.exit(1);
}

console.log(`nexusq version: ${version()}`);

const dir = mkdtempSync(join(tmpdir(), "nexusq_ts_smoke_"));
const path = join(dir, "vault.nqv");

try {
  const vault = Vault.create(path, "typescript-test", "typescript-smoke");

  if (!existsSync(path)) fail("vault file was not created");
  if (vault.path !== path) fail("vault.path does not match input");
  if (vault.formatVersion !== 1) fail(`format_version must be 1, got ${vault.formatVersion}`);

  console.log(`vault created at ${vault.path}`);
  console.log(`vault format version: ${vault.formatVersion}`);

  let raised = false;
  try {
    Vault.create(join(dir, "no", "parent", "vault.nqv"), "x", null);
  } catch (e) {
    raised = true;
    if (!(e instanceof Error) || !e.message) fail("error without message");
  }
  if (!raised) fail("creating a vault under a missing directory must fail");

  console.log("error propagation: ok");
  console.log("smoke test passed");
} finally {
  rmSync(dir, { recursive: true, force: true });
}
