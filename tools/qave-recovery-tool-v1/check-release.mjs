import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readdir, readFile, stat } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const publicKeyID = "qave-recovery-2026-v1";
const publicKeyFingerprint16 = "6f76e166bd24a1dc";
const expectedEntries = new Set([
  "index.html",
  "style.css",
  "app.mjs",
  "core.mjs",
  "README.md",
  "RELEASE-MANIFEST.json",
]);
const codeEntries = ["index.html", "style.css", "app.mjs", "core.mjs"];
const releaseFileEntries = ["index.html", "style.css", "app.mjs", "core.mjs", "README.md"];
const crcTable = buildCRCTable();

const scriptPath = fileURLToPath(import.meta.url);
const toolDir = path.dirname(scriptPath);
const repoRoot = path.resolve(toolDir, "..", "..");
const defaultOutputDir = path.resolve(repoRoot, "dist", "recovery-tool");

try {
  const zipPath = path.resolve(process.argv[2] || (await latestZipPath(defaultOutputDir)));
  const zipBytes = await readFile(zipPath);
  const zipSHA256 = sha256Hex(zipBytes);
  const entries = parseStoredZip(zipBytes);

  assertExpectedEntries(entries);
  assertNoForbiddenPaths(entries);
  assertNoForbiddenContent(entries);

  const manifest = JSON.parse(entries.get("RELEASE-MANIFEST.json").data.toString("utf8"));
  assertManifestShape(manifest);
  assertManifestFileRecords(manifest, entries, releaseFileEntries);
  assertCSP(entries.get("index.html").data.toString("utf8"));

  const sidecarManifestPath = path.join(path.dirname(zipPath), `${path.basename(zipPath, ".zip")}.manifest.json`);
  const sidecarManifest = JSON.parse(await readFile(sidecarManifestPath, "utf8"));
  assertSidecarManifest(sidecarManifest, entries, zipSHA256);

  const sha256Sidecar = await readFile(`${zipPath}.sha256`, "utf8");
  const sidecarHash = sha256Sidecar.trim().split(/\s+/)[0];
  if (sidecarHash !== zipSHA256) {
    fail(`zip .sha256 sidecar mismatch: expected ${zipSHA256}, got ${sidecarHash}`);
  }

  console.log("release_check=ok");
  console.log(`zip_path=${zipPath}`);
  console.log(`zip_sha256=${zipSHA256}`);
  console.log(`sidecar_manifest=${sidecarManifestPath}`);
  console.log(`public_key_fingerprint_16=${publicKeyFingerprint16}`);
} catch (error) {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
}

async function latestZipPath(outputDir) {
  const names = (await readdir(outputDir)).filter((name) => name.endsWith(".zip"));
  if (names.length === 0) {
    throw new Error(`no release zip found in ${outputDir}`);
  }
  const withStats = await Promise.all(
    names.map(async (name) => ({
      name,
      stats: await stat(path.join(outputDir, name)),
    })),
  );
  withStats.sort((left, right) => right.stats.mtimeMs - left.stats.mtimeMs);
  return path.join(outputDir, withStats[0].name);
}

function assertExpectedEntries(entries) {
  for (const expected of expectedEntries) {
    if (!entries.has(expected)) {
      fail(`release zip is missing ${expected}`);
    }
  }
  for (const name of entries.keys()) {
    if (!expectedEntries.has(name)) {
      fail(`release zip contains unexpected file: ${name}`);
    }
  }
}

function assertNoForbiddenPaths(entries) {
  for (const name of entries.keys()) {
    if (name.includes("..") || path.isAbsolute(name)) {
      fail(`release zip contains unsafe path: ${name}`);
    }
    if (
      name === "core.test.mjs" ||
      name.includes("node_modules/") ||
      name.includes(".git/") ||
      /\.(qrm|ciphertext|enc|key|pem|seed)$/i.test(name)
    ) {
      fail(`release zip contains forbidden file: ${name}`);
    }
  }
}

function assertNoForbiddenContent(entries) {
  const codePatterns = [
    ["fetch()", /\bfetch\s*\(/],
    ["XMLHttpRequest", /\bXMLHttpRequest\b/],
    ["sendBeacon", /\bsendBeacon\b/],
    ["localStorage", /\blocalStorage\b/],
    ["sessionStorage", /\bsessionStorage\b/],
    ["IndexedDB", /\bindexedDB\b|\bIndexedDB\b/],
    ["serviceWorker", /\bserviceWorker\b/],
    ["analytics", /\banalytics\b/i],
    ["sentry", /\bsentry\b/i],
    ["rollbar", /\brollbar\b/i],
    ["posthog", /\bposthog\b/i],
    ["mixpanel", /\bmixpanel\b/i],
    ["datadog", /\bdatadog\b/i],
    ["gtag", /\bgtag\b/i],
  ];
  for (const entryName of codeEntries) {
    const text = entries.get(entryName).data.toString("utf8");
    for (const [label, pattern] of codePatterns) {
      if (pattern.test(text)) {
        fail(`${entryName} contains forbidden API or telemetry marker: ${label}`);
      }
    }
  }

  const secretPatterns = [
    ["RECOVERY_SIGNING_SECRET", /\b[A-Z0-9_]*RECOVERY[A-Z0-9_]*(?:SIGNING|SECRET|SEED)[A-Z0-9_]*\b/],
    ["PAYER_PRIVATE_KEY", /\b[A-Z0-9_]*PAYER[A-Z0-9_]*PRIVATE[A-Z0-9_]*KEY[A-Z0-9_]*\b/],
    ["PRIVATE_KEY", /\bPRIVATE_KEY\b|-----BEGIN [A-Z ]*PRIVATE KEY-----/],
    ["SECRET_SEED", /\bSECRET_SEED\b|\b[A-Z0-9_]*SEED[A-Z0-9_]*BASE64\b/],
    ["private seed", /\bprivate seed\b/i],
  ];
  for (const [entryName, entry] of entries) {
    const text = entry.data.toString("utf8");
    for (const [label, pattern] of secretPatterns) {
      if (pattern.test(text)) {
        fail(`${entryName} contains forbidden secret marker: ${label}`);
      }
    }
  }
}

function assertManifestShape(manifest) {
  if (manifest.tool_name !== "Qave Recovery Tool v1") {
    fail("manifest tool_name is incorrect");
  }
  if (manifest.qave_recovery_public_key_id !== publicKeyID) {
    fail("manifest public key id is incorrect");
  }
  if (manifest.qave_recovery_public_key_fingerprint_16 !== publicKeyFingerprint16) {
    fail("manifest public key fingerprint is incorrect");
  }
  const currentHead = git(["rev-parse", "HEAD"]);
  if (manifest.source_commit !== currentHead || manifest.commit_sha !== currentHead) {
    fail("manifest source commit does not match current HEAD");
  }
  const requiredSecurityFlags = [
    "no_qave_api",
    "no_backend_proxy",
    "no_analytics",
    "no_storage_api_for_secrets",
    "no_service_worker",
    "connect_src_none",
    "user_initiated_encrypted_file_download",
    "manual_ciphertext_upload",
  ];
  for (const flag of requiredSecurityFlags) {
    if (manifest.security_shape?.[flag] !== true) {
      fail(`manifest security_shape.${flag} must be true`);
    }
  }
}

function assertManifestFileRecords(manifest, entries, expectedFiles) {
  const records = new Map((manifest.files || []).map((record) => [record.path, record]));
  for (const filePath of expectedFiles) {
    const record = records.get(filePath);
    if (!record) {
      fail(`manifest missing file record for ${filePath}`);
    }
    const actual = entries.get(filePath).data;
    if (record.bytes !== actual.byteLength) {
      fail(`manifest byte size mismatch for ${filePath}`);
    }
    if (record.sha256 !== sha256Hex(actual)) {
      fail(`manifest sha256 mismatch for ${filePath}`);
    }
  }
}

function assertSidecarManifest(manifest, entries, zipSHA256) {
  if (manifest.zip_sha256 !== zipSHA256) {
    fail("sidecar manifest zip_sha256 does not match actual zip");
  }
  assertManifestShape(manifest);
  assertManifestFileRecords(manifest, entries, [...releaseFileEntries, "RELEASE-MANIFEST.json"]);
}

function assertCSP(indexHTML) {
  if (!/Content-Security-Policy/i.test(indexHTML)) {
    fail("index.html is missing Content-Security-Policy");
  }
  if (!/connect-src\s+'none'/.test(indexHTML)) {
    fail("index.html CSP must keep connect-src 'none'");
  }
  if (!/script-src\s+'self'/.test(indexHTML)) {
    fail("index.html CSP must keep script-src 'self'");
  }
}

function parseStoredZip(buffer) {
  const eocdOffset = findEOCD(buffer);
  const entryCount = buffer.readUInt16LE(eocdOffset + 10);
  const centralDirectoryOffset = buffer.readUInt32LE(eocdOffset + 16);
  let offset = centralDirectoryOffset;
  const entries = new Map();

  for (let index = 0; index < entryCount; index += 1) {
    if (buffer.readUInt32LE(offset) !== 0x02014b50) {
      fail("invalid zip central directory");
    }
    const method = buffer.readUInt16LE(offset + 10);
    const crc = buffer.readUInt32LE(offset + 16);
    const compressedSize = buffer.readUInt32LE(offset + 20);
    const uncompressedSize = buffer.readUInt32LE(offset + 24);
    const nameLength = buffer.readUInt16LE(offset + 28);
    const extraLength = buffer.readUInt16LE(offset + 30);
    const commentLength = buffer.readUInt16LE(offset + 32);
    const localHeaderOffset = buffer.readUInt32LE(offset + 42);
    const name = buffer.subarray(offset + 46, offset + 46 + nameLength).toString("utf8");

    if (method !== 0) {
      fail(`zip entry is compressed instead of stored: ${name}`);
    }
    if (buffer.readUInt32LE(localHeaderOffset) !== 0x04034b50) {
      fail(`invalid local zip header for ${name}`);
    }
    const localNameLength = buffer.readUInt16LE(localHeaderOffset + 26);
    const localExtraLength = buffer.readUInt16LE(localHeaderOffset + 28);
    const dataStart = localHeaderOffset + 30 + localNameLength + localExtraLength;
    const data = buffer.subarray(dataStart, dataStart + compressedSize);
    if (data.byteLength !== uncompressedSize) {
      fail(`zip entry size mismatch for ${name}`);
    }
    if (crc32(data) !== crc) {
      fail(`zip entry crc mismatch for ${name}`);
    }
    entries.set(name, { data, compressedSize, uncompressedSize });
    offset += 46 + nameLength + extraLength + commentLength;
  }
  return entries;
}

function findEOCD(buffer) {
  const minOffset = Math.max(0, buffer.length - 65557);
  for (let offset = buffer.length - 22; offset >= minOffset; offset -= 1) {
    if (buffer.readUInt32LE(offset) === 0x06054b50) {
      return offset;
    }
  }
  fail("zip end-of-central-directory not found");
}

function git(args) {
  return execFileSync("git", args, {
    cwd: repoRoot,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "ignore"],
  }).trim();
}

function sha256Hex(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function crc32(bytes) {
  let crc = 0xffffffff;
  for (const byte of bytes) {
    crc = (crc >>> 8) ^ crcTable[(crc ^ byte) & 0xff];
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function buildCRCTable() {
  return Array.from({ length: 256 }, (_, index) => {
    let value = index;
    for (let bit = 0; bit < 8; bit += 1) {
      value = value & 1 ? 0xedb88320 ^ (value >>> 1) : value >>> 1;
    }
    return value >>> 0;
  });
}

function fail(message) {
  throw new Error(message);
}
