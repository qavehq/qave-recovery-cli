import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const toolName = "Qave Recovery Tool v1";
const publicKeyID = "qave-recovery-2026-v1";
const publicKeyFingerprint16 = "6f76e166bd24a1dc";
const releaseFileNames = ["index.html", "style.css", "app.mjs", "core.mjs", "README.md"];
const manifestFileName = "RELEASE-MANIFEST.json";

const scriptPath = fileURLToPath(import.meta.url);
const toolDir = path.dirname(scriptPath);
const repoRoot = path.resolve(toolDir, "..", "..");
const outputDir = path.resolve(repoRoot, "dist", "recovery-tool");

const commitSha = git(["rev-parse", "HEAD"]);
const shortSha = commitSha.slice(0, 12);
const releaseID = sanitizeReleaseID(process.env.RECOVERY_TOOL_RELEASE || process.env.VERSION || `v1-${shortSha}`);
const archiveBaseName = releaseIDHasToolMajorVersion(releaseID)
  ? `qave-recovery-tool-${releaseID}`
  : `qave-recovery-tool-v1-${releaseID}`;
const zipPath = path.join(outputDir, `${archiveBaseName}.zip`);
const zipSHA256Path = `${zipPath}.sha256`;
const sidecarManifestPath = path.join(outputDir, `${archiveBaseName}.manifest.json`);
const latestManifestPath = path.join(outputDir, manifestFileName);
const generatedAt = new Date().toISOString();
const crcTable = buildCRCTable();

const releaseFiles = [];
for (const fileName of releaseFileNames) {
  const absolutePath = path.join(toolDir, fileName);
  const bytes = await readFile(absolutePath);
  releaseFiles.push({
    path: fileName,
    data: bytes,
    sha256: sha256Hex(bytes),
    bytes: bytes.byteLength,
  });
}

const fileRecords = releaseFiles.map(({ path: filePath, sha256, bytes }) => ({
  path: filePath,
  sha256,
  bytes,
}));

const baseManifest = {
  tool_name: toolName,
  version: releaseID,
  release_id: releaseID,
  commit_sha: commitSha,
  source_commit: commitSha,
  generated_at: generatedAt,
  files: fileRecords,
  zip_sha256: null,
  zip_sha256_note:
    "The final zip SHA256 is written to the .zip.sha256 file and sidecar manifest. A manifest inside the zip cannot contain the final hash of the archive that contains it without changing that hash.",
  qave_recovery_public_key_id: publicKeyID,
  qave_recovery_public_key_fingerprint_16: publicKeyFingerprint16,
  security_shape: {
    no_qave_api: true,
    no_backend_proxy: true,
    no_analytics: true,
    no_storage_api_for_secrets: true,
    no_service_worker: true,
    connect_src_none: true,
    user_initiated_encrypted_file_download: true,
    manual_ciphertext_upload: true,
  },
};

const inZipManifestBytes = Buffer.from(`${JSON.stringify(baseManifest, null, 2)}\n`, "utf8");
const zipEntries = [
  ...releaseFiles.map((file) => ({ path: file.path, data: file.data })),
  { path: manifestFileName, data: inZipManifestBytes },
];
const zipBytes = createStoredZip(zipEntries);
const zipSHA256 = sha256Hex(zipBytes);

const sidecarManifest = {
  ...baseManifest,
  zip_file: path.basename(zipPath),
  zip_sha256: zipSHA256,
  files: [
    ...fileRecords,
    {
      path: manifestFileName,
      sha256: sha256Hex(inZipManifestBytes),
      bytes: inZipManifestBytes.byteLength,
    },
  ],
  in_zip_manifest_zip_sha256: null,
};
const sidecarManifestBytes = Buffer.from(`${JSON.stringify(sidecarManifest, null, 2)}\n`, "utf8");

await mkdir(outputDir, { recursive: true });
await writeFile(zipPath, zipBytes);
await writeFile(zipSHA256Path, `${zipSHA256}  ${path.basename(zipPath)}\n`);
await writeFile(sidecarManifestPath, sidecarManifestBytes);
await writeFile(latestManifestPath, sidecarManifestBytes);

console.log(`zip_path=${zipPath}`);
console.log(`zip_sha256=${zipSHA256}`);
console.log(`sidecar_manifest=${sidecarManifestPath}`);
console.log(`latest_manifest=${latestManifestPath}`);
console.log(`public_key_fingerprint_16=${publicKeyFingerprint16}`);
console.log(`commit_sha=${commitSha}`);
for (const file of fileRecords) {
  console.log(`file_sha256 ${file.path} ${file.sha256} ${file.bytes}`);
}
console.log(`file_sha256 ${manifestFileName} ${sha256Hex(inZipManifestBytes)} ${inZipManifestBytes.byteLength}`);

function git(args) {
  return execFileSync("git", args, {
    cwd: repoRoot,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "ignore"],
  }).trim();
}

function sanitizeReleaseID(value) {
  const normalized = `${value ?? ""}`.trim().replace(/[^0-9A-Za-z._-]+/g, "-").replace(/^-+|-+$/g, "");
  if (!normalized) {
    throw new Error("release id is empty");
  }
  return normalized;
}

function releaseIDHasToolMajorVersion(value) {
  return /^(?:v)?1(?:[.-]|$)/.test(value);
}

function sha256Hex(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function createStoredZip(entries) {
  const localParts = [];
  const centralParts = [];
  let offset = 0;

  for (const entry of entries) {
    const nameBytes = Buffer.from(entry.path, "utf8");
    const data = Buffer.from(entry.data);
    const crc = crc32(data);
    const localHeader = Buffer.alloc(30);
    localHeader.writeUInt32LE(0x04034b50, 0);
    localHeader.writeUInt16LE(20, 4);
    localHeader.writeUInt16LE(0, 6);
    localHeader.writeUInt16LE(0, 8);
    localHeader.writeUInt16LE(0, 10);
    localHeader.writeUInt16LE(0x0021, 12);
    localHeader.writeUInt32LE(crc, 14);
    localHeader.writeUInt32LE(data.length, 18);
    localHeader.writeUInt32LE(data.length, 22);
    localHeader.writeUInt16LE(nameBytes.length, 26);
    localHeader.writeUInt16LE(0, 28);
    localParts.push(localHeader, nameBytes, data);

    const centralHeader = Buffer.alloc(46);
    centralHeader.writeUInt32LE(0x02014b50, 0);
    centralHeader.writeUInt16LE(20, 4);
    centralHeader.writeUInt16LE(20, 6);
    centralHeader.writeUInt16LE(0, 8);
    centralHeader.writeUInt16LE(0, 10);
    centralHeader.writeUInt16LE(0, 12);
    centralHeader.writeUInt16LE(0x0021, 14);
    centralHeader.writeUInt32LE(crc, 16);
    centralHeader.writeUInt32LE(data.length, 20);
    centralHeader.writeUInt32LE(data.length, 24);
    centralHeader.writeUInt16LE(nameBytes.length, 28);
    centralHeader.writeUInt16LE(0, 30);
    centralHeader.writeUInt16LE(0, 32);
    centralHeader.writeUInt16LE(0, 34);
    centralHeader.writeUInt16LE(0, 36);
    centralHeader.writeUInt32LE(0, 38);
    centralHeader.writeUInt32LE(offset, 42);
    centralParts.push(centralHeader, nameBytes);

    offset += localHeader.length + nameBytes.length + data.length;
  }

  const centralDirectory = Buffer.concat(centralParts);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(0, 4);
  end.writeUInt16LE(0, 6);
  end.writeUInt16LE(entries.length, 8);
  end.writeUInt16LE(entries.length, 10);
  end.writeUInt32LE(centralDirectory.length, 12);
  end.writeUInt32LE(offset, 16);
  end.writeUInt16LE(0, 20);

  return Buffer.concat([...localParts, centralDirectory, end]);
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
