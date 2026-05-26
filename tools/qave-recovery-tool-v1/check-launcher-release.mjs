import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readdir, readFile, stat } from "node:fs/promises";
import { inflateRawSync } from "node:zlib";
import path from "node:path";
import { fileURLToPath } from "node:url";

const appName = "Qave Recovery Tool.app";
const executableName = "Qave Recovery Tool";
const bundleID = "com.qave.recovery-tool";
const publicKeyFingerprint16 = "6f76e166bd24a1dc";
const appPrefix = `${appName}/`;
const resourcesPrefix = `${appName}/Contents/Resources/recovery-tool/`;
const executablePath = `${appName}/Contents/MacOS/${executableName}`;
const infoPlistPath = `${appName}/Contents/Info.plist`;
const readmePath = "README.txt";
const releaseManifestPath = `${resourcesPrefix}RELEASE-MANIFEST.json`;
const expectedStaticFiles = new Set([
  "index.html",
  "style.css",
  "app.mjs",
  "core.mjs",
  "README.md",
  "RELEASE-MANIFEST.json",
]);
const expectedEntries = new Set([
  appPrefix,
  `${appName}/Contents/`,
  `${appName}/Contents/MacOS/`,
  executablePath,
  `${appName}/Contents/Resources/`,
  resourcesPrefix,
  `${resourcesPrefix}index.html`,
  `${resourcesPrefix}style.css`,
  `${resourcesPrefix}app.mjs`,
  `${resourcesPrefix}core.mjs`,
  `${resourcesPrefix}README.md`,
  releaseManifestPath,
  infoPlistPath,
  readmePath,
]);
const forbiddenNames = new Set([
  "core.test.mjs",
  "package-release.mjs",
  "package-launcher-release.mjs",
  "check-release.mjs",
  "check-launcher-release.mjs",
  "RELEASE-NOTES-v1.0.0-rc.1.md",
]);
const defaultOutputDir = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "..",
  "..",
  "dist",
  "recovery-tool-launcher",
);
const crcTable = Array.from({ length: 256 }, (_, index) => {
  let value = index;
  for (let bit = 0; bit < 8; bit += 1) {
    value = value & 1 ? 0xedb88320 ^ (value >>> 1) : value >>> 1;
  }
  return value >>> 0;
});

try {
  const zipPath = path.resolve(process.argv[2] || (await latestZipPath(defaultOutputDir)));
  const zipBytes = await readFile(zipPath);
  const zipSHA256 = sha256Hex(zipBytes);
  const entries = parseZip(zipBytes);

  assertZipEntries(entries);
  assertForbiddenPaths(entries);
  assertStaticFiles(entries);
  assertInfoPlist(entries.get(infoPlistPath).data.toString("utf8"));
  assertReadme(entries.get(readmePath).data.toString("utf8"));
  assertExecutable(entries.get(executablePath));
  assertForbiddenContent(entries);

  const sidecarManifestPath = path.join(path.dirname(zipPath), `${path.basename(zipPath, ".zip")}.manifest.json`);
  const sidecarManifest = JSON.parse(await readFile(sidecarManifestPath, "utf8"));
  assertLauncherManifest(sidecarManifest, zipSHA256);

  const inZipManifest = JSON.parse(entries.get(releaseManifestPath).data.toString("utf8"));
  assertReleaseManifest(inZipManifest);

  const sha256Sidecar = await readFile(`${zipPath}.sha256`, "utf8");
  const sidecarHash = sha256Sidecar.trim().split(/\s+/)[0];
  if (sidecarHash !== zipSHA256) {
    fail(`zip .sha256 sidecar mismatch: expected ${zipSHA256}, got ${sidecarHash}`);
  }

  console.log("launcher_release_check=ok");
  console.log(`launcher_zip_path=${zipPath}`);
  console.log(`launcher_zip_sha256=${zipSHA256}`);
  console.log(`launcher_manifest=${sidecarManifestPath}`);
  console.log(`public_key_fingerprint_16=${publicKeyFingerprint16}`);
} catch (error) {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
}

async function latestZipPath(outputDir) {
  const names = (await readdir(outputDir)).filter((name) => name.endsWith(".zip"));
  if (names.length === 0) {
    throw new Error(`no launcher release zip found in ${outputDir}`);
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

function assertZipEntries(entries) {
  for (const required of [executablePath, infoPlistPath, readmePath, releaseManifestPath]) {
    if (!entries.has(required)) {
      fail(`launcher zip is missing required entry: ${required}`);
    }
  }
  for (const name of entries.keys()) {
    if (!expectedEntries.has(name)) {
      fail(`launcher zip contains unexpected entry: ${name}`);
    }
    if (!(name === readmePath || name.startsWith(appPrefix))) {
      fail(`launcher zip contains unexpected top-level entry: ${name}`);
    }
  }
}

function assertForbiddenPaths(entries) {
  for (const name of entries.keys()) {
    const base = path.posix.basename(name.replace(/\/$/, ""));
    if (name.includes("..") || path.posix.isAbsolute(name) || name.includes("\\")) {
      fail(`launcher zip contains unsafe path: ${name}`);
    }
    if (
      forbiddenNames.has(base) ||
      name.includes("node_modules/") ||
      name.includes(".git/") ||
      /\.(qrm|ciphertext|enc|key|pem|seed)$/i.test(base)
    ) {
      fail(`launcher zip contains forbidden file: ${name}`);
    }
  }
}

function assertStaticFiles(entries) {
  const actualStaticFiles = [];
  for (const name of entries.keys()) {
    if (!name.startsWith(resourcesPrefix) || name === resourcesPrefix) {
      continue;
    }
    const relative = name.slice(resourcesPrefix.length);
    if (relative.includes("/")) {
      fail(`recovery-tool resource contains nested path: ${name}`);
    }
    actualStaticFiles.push(relative);
    if (!expectedStaticFiles.has(relative)) {
      fail(`recovery-tool resource contains unexpected file: ${relative}`);
    }
  }
  for (const expected of expectedStaticFiles) {
    if (!actualStaticFiles.includes(expected)) {
      fail(`recovery-tool resource is missing ${expected}`);
    }
  }
}

function assertInfoPlist(infoPlist) {
  const identifier = plistString(infoPlist, "CFBundleIdentifier");
  if (identifier !== bundleID) {
    fail(`Info.plist CFBundleIdentifier is ${identifier}, expected ${bundleID}`);
  }
  const executable = plistString(infoPlist, "CFBundleExecutable");
  if (executable !== executableName) {
    fail(`Info.plist CFBundleExecutable is ${executable}, expected ${executableName}`);
  }
}

function plistString(infoPlist, key) {
  const pattern = new RegExp(`<key>${escapeRegExp(key)}</key>\\s*<string>([^<]+)</string>`);
  const match = infoPlist.match(pattern);
  if (!match) {
    fail(`Info.plist is missing ${key}`);
  }
  return match[1];
}

function assertReadme(readme) {
  const forbidden = [
    ["/Users/lvbu007", /\/Users\/lvbu007/],
    ["qave-lab", /qave-lab/i],
    ["/tmp", /\/tmp\b/],
  ];
  for (const [label, pattern] of forbidden) {
    if (pattern.test(readme)) {
      fail(`README.txt contains forbidden local/internal path marker: ${label}`);
    }
  }
}

function assertExecutable(entry) {
  const unixMode = entry.externalAttrs >>> 16;
  if ((unixMode & 0o111) === 0) {
    fail("launcher binary is not marked executable in the zip");
  }
}

function assertForbiddenContent(entries) {
  const secretPatterns = [
    ["private key block", /-----BEGIN [A-Z ]*PRIVATE KEY-----/],
    ["private seed", /\bprivate seed\b/i],
    ["PRIVATE_KEY", /\bPRIVATE_KEY\b/],
    ["SECRET_SEED", /\bSECRET_SEED\b/],
  ];
  for (const [entryName, entry] of entries) {
    if (entryName === executablePath || entry.isDirectory) {
      continue;
    }
    const text = entry.data.toString("utf8");
    for (const [label, pattern] of secretPatterns) {
      if (pattern.test(text)) {
        fail(`${entryName} contains forbidden secret marker: ${label}`);
      }
    }
  }
}

function assertLauncherManifest(manifest, zipSHA256) {
  if (manifest.package_type !== "macos_app_launcher_zip") {
    fail("launcher manifest package_type is incorrect");
  }
  if (manifest.zip_sha256 !== zipSHA256) {
    fail("launcher manifest zip_sha256 does not match actual zip");
  }
  assertReleaseManifest(manifest);
  if (manifest.app_bundle !== appName) {
    fail("launcher manifest app_bundle is incorrect");
  }
  if (manifest.app_executable !== executablePath) {
    fail("launcher manifest app_executable is incorrect");
  }
  if (manifest.static_root !== `${appName}/Contents/Resources/recovery-tool`) {
    fail("launcher manifest static_root is incorrect");
  }

  const shape = manifest.launcher_security_shape || {};
  const requiredTrueFlags = [
    "binds_localhost_only",
    "random_localhost_port",
    "no_qave_api",
    "no_backend_proxy",
    "no_file_upload_api",
    "no_user_file_read",
    "no_telemetry",
  ];
  for (const flag of requiredTrueFlags) {
    if (shape[flag] !== true) {
      fail(`launcher manifest launcher_security_shape.${flag} must be true`);
    }
  }
  if (!Array.isArray(shape.static_file_allowlist)) {
    fail("launcher manifest launcher_security_shape.static_file_allowlist must be an array");
  }
  const allowlist = new Set(shape.static_file_allowlist);
  for (const expected of expectedStaticFiles) {
    if (!allowlist.has(expected)) {
      fail(`launcher manifest static_file_allowlist is missing ${expected}`);
    }
  }
  if (allowlist.size !== expectedStaticFiles.size) {
    fail("launcher manifest static_file_allowlist contains unexpected files");
  }
}

function assertReleaseManifest(manifest) {
  if (manifest.tool_name !== "Qave Recovery Tool v1") {
    fail("manifest tool_name is incorrect");
  }
  if (manifest.qave_recovery_public_key_fingerprint_16 !== publicKeyFingerprint16) {
    fail("manifest public key fingerprint is incorrect");
  }
  const currentHead = git(["rev-parse", "HEAD"]);
  if (manifest.commit_sha !== currentHead || manifest.source_commit !== currentHead) {
    fail("manifest commit does not match current HEAD");
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

function parseZip(buffer) {
  const eocdOffset = findEOCD(buffer);
  const entryCount = buffer.readUInt16LE(eocdOffset + 10);
  const centralDirectoryOffset = buffer.readUInt32LE(eocdOffset + 16);
  let offset = centralDirectoryOffset;
  const entries = new Map();

  for (let index = 0; index < entryCount; index += 1) {
    if (buffer.readUInt32LE(offset) !== 0x02014b50) {
      fail("invalid zip central directory");
    }
    const versionMadeBy = buffer.readUInt16LE(offset + 4);
    const method = buffer.readUInt16LE(offset + 10);
    const crc = buffer.readUInt32LE(offset + 16);
    const compressedSize = buffer.readUInt32LE(offset + 20);
    const uncompressedSize = buffer.readUInt32LE(offset + 24);
    const nameLength = buffer.readUInt16LE(offset + 28);
    const extraLength = buffer.readUInt16LE(offset + 30);
    const commentLength = buffer.readUInt16LE(offset + 32);
    const externalAttrs = buffer.readUInt32LE(offset + 38);
    const localHeaderOffset = buffer.readUInt32LE(offset + 42);
    const name = buffer.subarray(offset + 46, offset + 46 + nameLength).toString("utf8");

    if (buffer.readUInt32LE(localHeaderOffset) !== 0x04034b50) {
      fail(`invalid local zip header for ${name}`);
    }
    const localNameLength = buffer.readUInt16LE(localHeaderOffset + 26);
    const localExtraLength = buffer.readUInt16LE(localHeaderOffset + 28);
    const dataStart = localHeaderOffset + 30 + localNameLength + localExtraLength;
    const compressed = buffer.subarray(dataStart, dataStart + compressedSize);
    const data = decompressEntry(name, method, compressed);
    if (data.byteLength !== uncompressedSize) {
      fail(`zip entry size mismatch for ${name}`);
    }
    if (crc32(data) !== crc) {
      fail(`zip entry crc mismatch for ${name}`);
    }
    entries.set(name, {
      data,
      externalAttrs,
      isDirectory: name.endsWith("/"),
      versionMadeBy,
    });
    offset += 46 + nameLength + extraLength + commentLength;
  }
  return entries;
}

function decompressEntry(name, method, compressed) {
  if (method === 0) {
    return compressed;
  }
  if (method === 8) {
    return inflateRawSync(compressed);
  }
  fail(`unsupported zip compression method ${method} for ${name}`);
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
    cwd: path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", ".."),
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

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function fail(message) {
  throw new Error(message);
}
