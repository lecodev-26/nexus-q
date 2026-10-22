const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

if (process.env.NEXUSQ_LIBRARY || process.env.NEXUSQ_SKIP_NATIVE_DOWNLOAD === "1") {
  process.exit(0);
}

const pkg = require("../package.json");
const platform = `${process.platform}-${process.arch}`;
if (process.platform === "linux" && !process.report?.getReport?.().header?.glibcVersionRuntime) {
  throw new Error("NEXUS-Q prebuilt Linux runtimes require glibc (not musl/Alpine). Set NEXUSQ_LIBRARY to a compatible build.");
}
const assets = {
  "linux-x64": ["nexusq-sdk-runtime-linux-x64.so", "libnexusq.so"],
  "linux-arm64": ["nexusq-sdk-runtime-linux-arm64.so", "libnexusq.so"],
  "darwin-arm64": ["nexusq-sdk-runtime-macos-arm64.dylib", "libnexusq.dylib"],
  "win32-x64": ["nexusq-sdk-runtime-windows-x64.dll", "nexusq.dll"],
};
const selected = assets[platform];
if (!selected) {
  throw new Error(`NEXUS-Q does not publish a native runtime for ${platform}. Set NEXUSQ_LIBRARY to a compatible library; Rust is not required when a prebuilt runtime is available.`);
}

const [asset, localName] = selected;
const base = (process.env.NEXUSQ_TEST_RUNTIME_BASE_URL || `https://github.com/lecodev-26/nexus-q/releases/download/v${pkg.version}`).replace(/\/$/, "");
const destination = path.join(__dirname, "..", "vendor", localName);
const temp = `${destination}.download`;

async function main() {
  const checksumsResponse = await fetch(`${base}/NATIVE-RUNTIME-SHA256SUMS`, { signal: AbortSignal.timeout(30_000) });
  if (!checksumsResponse.ok) throw new Error(`Cannot fetch NEXUS-Q ${pkg.version} runtime checksums (HTTP ${checksumsResponse.status}).`);
  const checksums = await checksumsResponse.text();
  const line = checksums.split(/\r?\n/).find((entry) => entry.trim().endsWith(`  ${asset}`));
  if (!line) throw new Error(`NEXUS-Q ${pkg.version} release has no checksum for ${asset}.`);
  const expected = line.trim().split(/\s+/)[0].toLowerCase();

  const response = await fetch(`${base}/${asset}`, { signal: AbortSignal.timeout(60_000) });
  if (!response.ok) throw new Error(`Cannot fetch NEXUS-Q native runtime ${asset} (HTTP ${response.status}).`);
  const bytes = Buffer.from(await response.arrayBuffer());
  const actual = crypto.createHash("sha256").update(bytes).digest("hex");
  if (actual !== expected) throw new Error(`SHA-256 mismatch for ${asset}; refusing to install an unverified native runtime.`);

  fs.mkdirSync(path.dirname(destination), { recursive: true });
  fs.writeFileSync(temp, bytes, { mode: 0o755 });
  fs.renameSync(temp, destination);
  console.log(`Installed verified NEXUS-Q ${pkg.version} native runtime for ${platform}.`);
}

main().catch((error) => {
  try { fs.rmSync(temp, { force: true }); } catch {}
  console.error(`${error.message}\nIf building from a source checkout, set NEXUSQ_SKIP_NATIVE_DOWNLOAD=1 and set NEXUSQ_LIBRARY for smoke tests.`);
  process.exitCode = 1;
});
