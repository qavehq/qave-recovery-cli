import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { chmod, cp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const appName = "Qave Recovery Tool";
const bundleID = "com.qave.recovery-tool";
const staticFileNames = ["index.html", "style.css", "app.mjs", "core.mjs", "README.md"];
const manifestFileName = "RELEASE-MANIFEST.json";
const publicKeyID = "qave-recovery-2026-v1";
const publicKeyFingerprint16 = "6f76e166bd24a1dc";

const scriptPath = fileURLToPath(import.meta.url);
const toolDir = path.dirname(scriptPath);
const repoRoot = path.resolve(toolDir, "..", "..");
const outputDir = path.resolve(repoRoot, "dist", "recovery-tool-launcher");
const stagingRoot = path.resolve(outputDir, ".staging");
const commitSha = git(["rev-parse", "HEAD"]);
const shortSha = commitSha.slice(0, 12);
const releaseID = sanitizeReleaseID(process.env.RECOVERY_TOOL_RELEASE || process.env.VERSION || `v1-${shortSha}`);
const generatedAt = new Date().toISOString();
const targets = parseTargets(process.argv.slice(2));

await rm(stagingRoot, { recursive: true, force: true });
await mkdir(outputDir, { recursive: true });

for (const target of targets) {
  const [goos, goarch] = target.split("/");
  if (goos !== "darwin") {
    throw new Error(`unsupported launcher target ${target}; B4-1 packages macOS .app bundles only`);
  }

  const archiveBaseName = `qave-recovery-tool-macos-${goarch}-${releaseID}`;
  const targetStagingRoot = path.join(stagingRoot, `${goos}-${goarch}`);
  const appRoot = path.join(targetStagingRoot, `${appName}.app`);
  const contentsDir = path.join(appRoot, "Contents");
  const macOSDir = path.join(contentsDir, "MacOS");
  const resourcesDir = path.join(contentsDir, "Resources");
  const recoveryToolDir = path.join(resourcesDir, "recovery-tool");
  const binaryPath = path.join(macOSDir, appName);
  const readmePath = path.join(targetStagingRoot, "README.txt");
  const archivePath = path.join(outputDir, `${archiveBaseName}.zip`);
  const checksumPath = `${archivePath}.sha256`;
  const manifestPath = path.join(outputDir, `${archiveBaseName}.manifest.json`);

  await rm(targetStagingRoot, { recursive: true, force: true });
  await mkdir(macOSDir, { recursive: true });
  await mkdir(recoveryToolDir, { recursive: true });

  for (const fileName of staticFileNames) {
    await cp(path.join(toolDir, fileName), path.join(recoveryToolDir, fileName));
  }

  const releaseManifest = await buildReleaseManifest({ archiveBaseName, goos, goarch });
  await writeFile(path.join(recoveryToolDir, manifestFileName), `${JSON.stringify(releaseManifest, null, 2)}\n`);
  await writeFile(path.join(contentsDir, "Info.plist"), infoPlist({ releaseID }));
  await writeFile(readmePath, readmeText({ releaseID, goarch }));

  buildLauncher({ goos, goarch, output: binaryPath });
  await chmod(binaryPath, 0o755);

  await rm(archivePath, { force: true });
  execFileSync("zip", ["-qry", archivePath, `${appName}.app`, "README.txt"], { cwd: targetStagingRoot, stdio: "inherit" });
  const zipSHA256 = sha256Hex(await readFile(archivePath));
  await writeFile(checksumPath, `${zipSHA256}  ${path.basename(archivePath)}\n`);

  const launcherManifest = {
    ...releaseManifest,
    package_type: "macos_app_launcher_zip",
    zip_file: path.basename(archivePath),
    zip_sha256: zipSHA256,
    app_bundle: `${appName}.app`,
    app_executable: `${appName}.app/Contents/MacOS/${appName}`,
    static_root: `${appName}.app/Contents/Resources/recovery-tool`,
    launcher_security_shape: {
      binds_localhost_only: true,
      random_localhost_port: true,
      static_file_allowlist: [...staticFileNames, manifestFileName],
      serves_allowlisted_static_files_only: true,
      no_qave_api: true,
      no_backend_proxy: true,
      no_file_upload_api: true,
      no_user_file_read: true,
      no_secret_storage: true,
      no_telemetry: true,
      no_auto_update: true,
    },
  };
  await writeFile(manifestPath, `${JSON.stringify(launcherManifest, null, 2)}\n`);

  console.log(`launcher_zip_path=${archivePath}`);
  console.log(`launcher_zip_sha256=${zipSHA256}`);
  console.log(`launcher_manifest=${manifestPath}`);
  console.log(`target=${target}`);
  console.log(`commit_sha=${commitSha}`);
}

await rm(stagingRoot, { recursive: true, force: true });

async function buildReleaseManifest({ archiveBaseName, goos, goarch }) {
  const files = [];
  for (const fileName of staticFileNames) {
    const bytes = await readFile(path.join(toolDir, fileName));
    files.push({ path: fileName, sha256: sha256Hex(bytes), bytes: bytes.byteLength });
  }
  return {
    tool_name: "Qave Recovery Tool v1",
    version: releaseID,
    release_id: releaseID,
    package_name: archiveBaseName,
    target: `${goos}/${goarch}`,
    commit_sha: commitSha,
    source_commit: commitSha,
    generated_at: generatedAt,
    files,
    zip_sha256: null,
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
}

function buildLauncher({ goos, goarch, output }) {
  execFileSync("go", ["build", "-trimpath", "-ldflags", "-s -w", "-o", output, "./cmd/recovery-tool-launcher"], {
    cwd: repoRoot,
    env: {
      ...process.env,
      GOOS: goos,
      GOARCH: goarch,
      CGO_ENABLED: "0",
      GOCACHE: path.join(repoRoot, "dist", "go-build-cache"),
      GOMODCACHE: path.join(repoRoot, "dist", "go-mod-cache"),
    },
    stdio: "inherit",
  });
}

function parseTargets(args) {
  if (args.length > 0) {
    return args;
  }
  const arch = process.arch === "x64" ? "amd64" : "arm64";
  return [`darwin/${arch}`];
}

function sanitizeReleaseID(value) {
  const normalized = `${value ?? ""}`.trim().replace(/[^0-9A-Za-z._-]+/g, "-").replace(/^-+|-+$/g, "");
  if (!normalized) {
    throw new Error("release id is empty");
  }
  return normalized;
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

function infoPlist({ releaseID }) {
  return `<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n<plist version="1.0">\n<dict>\n  <key>CFBundleDevelopmentRegion</key>\n  <string>en</string>\n  <key>CFBundleExecutable</key>\n  <string>${appName}</string>\n  <key>CFBundleIdentifier</key>\n  <string>${bundleID}</string>\n  <key>CFBundleName</key>\n  <string>${appName}</string>\n  <key>CFBundleDisplayName</key>\n  <string>${appName}</string>\n  <key>CFBundlePackageType</key>\n  <string>APPL</string>\n  <key>CFBundleShortVersionString</key>\n  <string>${releaseID}</string>\n  <key>CFBundleVersion</key>\n  <string>${releaseID}</string>\n  <key>LSMinimumSystemVersion</key>\n  <string>12.0</string>\n</dict>\n</plist>\n`;
}

function readmeText({ releaseID, goarch }) {
  return `Qave Recovery Tool ${releaseID} (${goarch})\n\nOpen Qave Recovery Tool.app to start recovery.\n\nThe app starts a temporary local server bound only to 127.0.0.1, opens your default browser, and serves only the recovery-tool files included in this package. It does not call Qave backend/API/proxy, does not read your Recovery Package until you select it in the browser page, does not read your Recovery Key outside the browser page, and does not upload files.\n\nDo not use GitHub's auto-generated Source code zip/tar.gz as the recovery package.\n`;
}
