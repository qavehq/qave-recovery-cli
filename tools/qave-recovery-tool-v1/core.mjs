export const recoverySignatureKeyID = "qave-recovery-2026-v1";
export const recoverySignatureAlgorithm = "Ed25519";
export const recoveryFlowVersion = "recover-all.v1";
export const recoveryMapSchema = "qave.recovery-map.v1";
export const recoveryPackageSchemaVersion = "qave.recovery-package.v1";
export const payloadProtectionWalletBoundEncrypted = "wallet_bound_encrypted";
export const payloadProtectionLegacyPlaintext = "legacy_plaintext";
export const signingScopeLegacyPerExport = "legacy_per_export";
export const signingScopeSessionBoundV1 = "session_bound_v1";
export const qaveRecoveryPublicKeyBase64 = "1cm1N4Sp8iqySIqLINsubusrZamVzYUsNZZr6bx5yuQ=";
export const qaveRecoveryPublicKeySHA256Hex =
  "6f76e166bd24a1dcd0f526528368e8832fa70ec629eb28eec188b39037fa6954";
export const qaveRecoveryPublicKeyFingerprint16 = "6f76e166bd24a1dc";

const challengeVersionLine = "qave-recovery:v1";
const challengePurpose = "unlock_recovery_payload";
const sessionChallengeVersionLine = "qave-recovery-export-session:v1";
const unlockKDFInfo = "qave-recovery-payload-unlock-key/v1";
const sessionSeedKDFInfo = "qave-recovery-export-session-seed/v1";
const recoveryKDFAlgorithmPBKDF2SHA256 = "PBKDF2-HMAC-SHA-256";
const recoveryKDFHashSHA256 = "SHA-256";
const recoveryKDFVersion1 = 1;
const recoveryDerivedKeyLengthBytes = 32;
const recoveryWrapAlgorithmAES256GCM = "AES-256-GCM";
const recoveryWrapVersion1 = 1;
const recoveryKeyMaterialVersion1 = 1;
const recoveryKeyAlphabet = "ABCDEFGHJKMNPQRSTUVWXYZ23456789";
const recoveryKeyRawLength = 20;
const aesGCMTagLength = 16;
const wrapIVLengthBytes = 12;
const fileKeyLengthBytes = 32;
const wrappedFileKeyLengthBytes = 48;
const recoveryPieceHostTypo = "calibration-pdp.infrafolio.com";
const recoveryPieceHostCanonical = "caliberation-pdp.infrafolio.com";

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

export class RecoveryToolError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "RecoveryToolError";
    this.code = code;
  }
}

export function safeErrorMessage(error) {
  if (error instanceof RecoveryToolError) {
    return `${error.code}: ${error.message}`;
  }
  return "RECOVERY_TOOL_ERROR: recovery could not continue";
}

function fail(code, message) {
  throw new RecoveryToolError(code, message);
}

export function qavePublicKeys() {
  return {
    [recoverySignatureKeyID]: decodeBase64(qaveRecoveryPublicKeyBase64),
  };
}

export async function qavePublicKeyFingerprint16() {
  return (await sha256Hex(decodeBase64(qaveRecoveryPublicKeyBase64))).slice(0, 16);
}

export function parseQRMText(text) {
  let doc;
  try {
    doc = JSON.parse(text);
  } catch {
    fail("QRM_CORRUPTED", "qrm is not valid json");
  }
  if (!isPlainObject(doc)) {
    fail("QRM_CORRUPTED", "qrm root must be a json object");
  }
  return doc;
}

export function summarizeQRM(doc) {
  const header = isPlainObject(doc?.header) ? doc.header : {};
  const signature = isPlainObject(header.qave_signature) ? header.qave_signature : {};
  return {
    key_id: `${signature.key_id ?? ""}`.trim(),
    vault_owner: `${header.vault_owner ?? ""}`.trim(),
    generated_at: `${header.generated_at ?? ""}`.trim(),
    subscription_expires_at: `${header.subscription_expires_at ?? ""}`.trim(),
    file_count: Number(signature.file_count ?? 0),
    package_id: `${header.package_id ?? ""}`.trim(),
  };
}

export async function evaluateQRMForUnlock(doc, options = {}) {
  try {
    const gate = await validateQRMForUnlock(doc, options);
    return {
      ok: true,
      gate,
      actions: actionPermissions({ packageVerified: true }),
    };
  } catch (error) {
    return {
      ok: false,
      code: error instanceof RecoveryToolError ? error.code : "RECOVERY_TOOL_ERROR",
      message: safeErrorMessage(error),
      actions: actionPermissions({}),
    };
  }
}

export async function validateQRMForUnlock(doc, options = {}) {
  await assertEd25519WebCryptoSupported();
  validateBasicQRMShape(doc);
  const signature = validateSignatureShape(doc.header.qave_signature);
  const manifestJSON = canonicalRecoverySignedManifestJSON(
    doc.header,
    signature.file_count,
    signature.recovery_flow_version,
  );
  const manifestBytes = utf8(manifestJSON);
  const manifestSHA256 = await sha256Hex(manifestBytes);
  if (manifestSHA256 !== `${signature.manifest_sha256 ?? ""}`.trim().toLowerCase()) {
    fail("QRM_SIGNATURE_INVALID", "qrm signed manifest hash does not match header");
  }

  const publicKeys = options.publicKeys ?? qavePublicKeys();
  const publicKey = publicKeys[signature.key_id];
  if (!(publicKey instanceof Uint8Array) || publicKey.length !== 32) {
    fail("QRM_SIGNATURE_KEY_UNKNOWN", "qrm signature key_id is unknown");
  }

  const signatureBytes = decodeBase64(signature.signature);
  if (signatureBytes.length !== 64) {
    fail("QRM_SIGNATURE_INVALID", "qrm signature must be base64 encoded Ed25519 signature");
  }
  let verified = false;
  try {
    verified = await verifyEd25519(publicKey, signatureBytes, manifestBytes);
  } catch (error) {
    if (isEd25519Unsupported(error)) {
      fail("BROWSER_CRYPTO_UNSUPPORTED", "Ed25519 WebCrypto is not supported by this browser");
    }
    fail("QRM_SIGNATURE_INVALID", "qrm signature verification failed");
  }
  if (!verified) {
    fail("QRM_SIGNATURE_INVALID", "qrm signature verification failed");
  }

  const packageExpiresAt = parseQRMTime(doc.header.subscription_expires_at, "subscription_expires_at");
  assertPackageNotExpired(packageExpiresAt, options.now);
  validateEncryptedPayloadMaterial(doc);

  return {
    doc,
    manifestJSON,
    manifestSHA256,
    manifestAAD: decodeHexToBytes(manifestSHA256),
    packageExpiresAt,
    signature,
  };
}

export async function assertEd25519WebCryptoSupported() {
  if (!globalThis.crypto?.subtle) {
    fail("BROWSER_CRYPTO_UNSUPPORTED", "WebCrypto is not available in this browser");
  }
  try {
    await globalThis.crypto.subtle.importKey(
      "raw",
      toArrayBuffer(decodeBase64(qaveRecoveryPublicKeyBase64)),
      { name: "Ed25519" },
      false,
      ["verify"],
    );
  } catch (error) {
    if (isEd25519Unsupported(error)) {
      fail("BROWSER_CRYPTO_UNSUPPORTED", "Ed25519 WebCrypto is not supported by this browser");
    }
    throw error;
  }
}

function validateBasicQRMShape(doc) {
  if (!isPlainObject(doc?.header)) {
    fail("QRM_CORRUPTED", "qrm header is missing");
  }
  const header = doc.header;
  if (`${header.schema ?? ""}`.trim() !== recoveryMapSchema) {
    fail("QRM_SCHEMA_UNSUPPORTED", "unsupported qrm schema");
  }
  const required = [
    header.map_id,
    header.package_id,
    header.generated_at,
    header.vault_owner,
    header.vault_state_hash,
    header.subscription_expires_at,
    header?.payload_encryption?.algorithm,
    header?.payload_encryption?.kdf,
    header?.payload_encryption?.nonce,
    header?.payload_encryption?.binding,
  ];
  if (required.some((value) => `${value ?? ""}`.trim() === "")) {
    fail("QRM_CORRUPTED", "qrm required header fields are missing");
  }
  normalizeWalletAddress(header.vault_owner);
  parseQRMTime(header.generated_at, "generated_at");
  parseQRMTime(header.subscription_expires_at, "subscription_expires_at");
}

function validateSignatureShape(signature) {
  if (!isPlainObject(signature)) {
    fail("QRM_SIGNATURE_MISSING", "qrm signature is missing");
  }
  const normalized = {
    key_id: `${signature.key_id ?? ""}`.trim(),
    algorithm: `${signature.algorithm ?? ""}`.trim(),
    recovery_flow_version: `${signature.recovery_flow_version ?? ""}`.trim(),
    file_count: Number(signature.file_count ?? -1),
    manifest_sha256: `${signature.manifest_sha256 ?? ""}`.trim().toLowerCase(),
    signature: `${signature.signature ?? ""}`.trim(),
  };
  if (
    !normalized.key_id ||
    !normalized.algorithm ||
    !normalized.recovery_flow_version ||
    !normalized.manifest_sha256 ||
    !normalized.signature
  ) {
    fail("QRM_SIGNATURE_INVALID", "qrm signature block is incomplete");
  }
  if (normalized.key_id !== recoverySignatureKeyID) {
    fail("QRM_SIGNATURE_KEY_UNKNOWN", "qrm signature key_id is unknown");
  }
  if (normalized.algorithm !== recoverySignatureAlgorithm) {
    fail("QRM_SIGNATURE_INVALID", "qrm signature algorithm is unsupported");
  }
  if (!Number.isInteger(normalized.file_count) || normalized.file_count < 0) {
    fail("QRM_SIGNATURE_INVALID", "qrm signed manifest metadata is incomplete");
  }
  if (!/^[0-9a-f]{64}$/.test(normalized.manifest_sha256)) {
    fail("QRM_SIGNATURE_INVALID", "qrm signed manifest hash is invalid");
  }
  return normalized;
}

function validateEncryptedPayloadMaterial(doc) {
  if (payloadProtectionOf(doc) !== payloadProtectionWalletBoundEncrypted) {
    fail("QRM_UNSIGNED_LEGACY_UNSUPPORTED", "Browser Recovery Tool v1 only accepts signed encrypted recovery packages");
  }
  if (`${doc.payload_ciphertext ?? ""}`.trim() === "" || `${doc.payload_tag ?? ""}`.trim() === "") {
    fail("QRM_CORRUPTED", "encrypted qrm is missing payload ciphertext material");
  }
  const tag = decodeBase64(doc.payload_tag);
  if (tag.length !== aesGCMTagLength) {
    fail("QRM_CORRUPTED", "payload_tag must be 16 bytes");
  }
  const nonce = decodeBase64(doc.header.payload_encryption.nonce);
  if (nonce.length !== wrapIVLengthBytes) {
    fail("QRM_CORRUPTED", "payload nonce length does not match AES-GCM requirements");
  }
  if (`${doc.header.payload_encryption.encoding ?? ""}`.trim() !== "base64") {
    fail("QRM_CORRUPTED", "encrypted qrm payload encoding must be base64");
  }
  switch (signingScopeOf(doc)) {
    case signingScopeLegacyPerExport:
      break;
    case signingScopeSessionBoundV1:
      if (`${doc.header.payload_encryption.signing_challenge ?? ""}`.trim() === "") {
        fail("QRM_CORRUPTED", "session-bound qrm is missing signing_challenge");
      }
      if (
        `${doc.header.payload_encryption.signing_scope_version ?? ""}`.trim() !== "" &&
        `${doc.header.payload_encryption.signing_scope_version ?? ""}`.trim() !== "v1"
      ) {
        fail("QRM_CORRUPTED", "unsupported session-bound signing_scope_version");
      }
      break;
    default:
      fail("QRM_CORRUPTED", "unknown signing scope");
  }
}

export function payloadProtectionOf(doc) {
  const explicit = `${doc?.header?.payload_encryption?.payload_protection ?? ""}`.trim();
  if (explicit) return explicit;
  if (doc?.payload) return payloadProtectionLegacyPlaintext;
  if (`${doc?.payload_ciphertext ?? ""}`.trim() || `${doc?.payload_tag ?? ""}`.trim()) {
    return payloadProtectionWalletBoundEncrypted;
  }
  return "";
}

export function signingScopeOf(doc) {
  const scope = `${doc?.header?.payload_encryption?.signing_scope ?? ""}`.trim();
  return scope || signingScopeLegacyPerExport;
}

export function buildRecoverySignedManifest(header, fileCount, flowVersion = recoveryFlowVersion) {
  return {
    file_count: Number(fileCount ?? 0),
    generated_at: `${header?.generated_at ?? ""}`.trim(),
    map_id: `${header?.map_id ?? ""}`.trim(),
    package_id: `${header?.package_id ?? ""}`.trim(),
    payload_encryption: {
      algorithm: `${header?.payload_encryption?.algorithm ?? ""}`.trim(),
      binding: `${header?.payload_encryption?.binding ?? ""}`.trim(),
      kdf: `${header?.payload_encryption?.kdf ?? ""}`.trim(),
      nonce: `${header?.payload_encryption?.nonce ?? ""}`.trim(),
    },
    recovery_flow_version: `${flowVersion ?? ""}`.trim(),
    schema: `${header?.schema ?? ""}`.trim(),
    subscription_expires_at: `${header?.subscription_expires_at ?? ""}`.trim(),
    vault_owner: `${header?.vault_owner ?? ""}`.trim().toLowerCase(),
    vault_state_hash: `${header?.vault_state_hash ?? ""}`.trim(),
  };
}

export function canonicalManifestJSON(value) {
  return JSON.stringify(sortRecursively(value));
}

export function canonicalRecoverySignedManifestJSON(header, fileCount, flowVersion = recoveryFlowVersion) {
  return canonicalManifestJSON(buildRecoverySignedManifest(header, fileCount, flowVersion));
}

export async function recoverySignedManifestHashHex(header, fileCount, flowVersion = recoveryFlowVersion) {
  return sha256Hex(utf8(canonicalRecoverySignedManifestJSON(header, fileCount, flowVersion)));
}

export function buildUnlockChallenge(doc) {
  switch (signingScopeOf(doc)) {
    case signingScopeLegacyPerExport:
      return buildLegacyPerExportChallenge(doc.header);
    case signingScopeSessionBoundV1: {
      const challenge = `${doc.header?.payload_encryption?.signing_challenge ?? ""}`.trim();
      if (!challenge) {
        fail("QRM_CORRUPTED", "session-bound qrm is missing signing_challenge");
      }
      return challenge;
    }
    default:
      fail("QRM_CORRUPTED", "unknown signing scope");
  }
}

export function buildLegacyPerExportChallenge(header) {
  const nonce = `${header?.payload_encryption?.nonce ?? ""}`.trim();
  const mapID = `${header?.map_id ?? ""}`.trim();
  const vaultOwner = normalizeWalletAddress(header?.vault_owner);
  const vaultStateHash = `${header?.vault_state_hash ?? ""}`.trim();
  const generatedAt = `${header?.generated_at ?? ""}`.trim();
  if (!nonce || !mapID || !vaultOwner || !vaultStateHash || !generatedAt) {
    fail("QRM_CORRUPTED", "challenge inputs are incomplete");
  }
  return [
    challengeVersionLine,
    `map_id=${mapID}`,
    `vault_owner=${vaultOwner}`,
    `vault_state_hash=${vaultStateHash}`,
    `generated_at=${generatedAt}`,
    `nonce=${nonce}`,
    `purpose=${challengePurpose}`,
  ].join("\n");
}

export async function unlockPayloadWithSignature(doc, signatureHex, walletAddress, options = {}) {
  const gate = options.gate ?? (await validateQRMForUnlock(doc, options));
  const reportedAddress = normalizeWalletAddress(walletAddress);
  const owner = normalizeWalletAddress(doc.header.vault_owner);
  if (reportedAddress !== owner) {
    fail("WALLET_ADDRESS_MISMATCH", "signature address does not match vault_owner");
  }

  const challenge = buildUnlockChallenge(doc);
  const payloadKey = await deriveUnlockKey(doc, challenge, signatureHex);
  try {
    const payload = await decryptPayload(doc, payloadKey, gate.manifestAAD);
    validateRecoveryPayloadBinding(doc, payload, options.now);
    return {
      payload,
      walletAddress: reportedAddress,
      challenge,
      actions: actionPermissions({ packageVerified: true, payloadUnlocked: true, payloadConsistent: true }),
    };
  } finally {
    zeroBytes(payloadKey);
  }
}

async function deriveUnlockKey(doc, challenge, signatureHex) {
  switch (signingScopeOf(doc)) {
    case signingScopeLegacyPerExport:
      return deriveLegacyUnlockKey(doc, challenge, signatureHex);
    case signingScopeSessionBoundV1: {
      const sessionSeed = await deriveSessionExportSeed(challenge, signatureHex, doc.header.vault_owner);
      try {
        return derivePayloadKeyFromSessionSeed(doc, sessionSeed);
      } finally {
        zeroBytes(sessionSeed);
      }
    }
    default:
      fail("QRM_CORRUPTED", "unknown signing scope");
  }
}

async function deriveLegacyUnlockKey(doc, challenge, signatureHex) {
  const signatureBytes = decodePersonalSignature(signatureHex);
  const header = doc.header;
  const normalizedOwner = normalizeWalletAddress(header.vault_owner);
  const challengeHash = await sha256Bytes(utf8(challenge));
  const signatureHash = await sha256Bytes(signatureBytes);
  const saltInput = [
    "qave-recovery-cli:v1",
    `map_id=${header.map_id}`,
    `vault_owner=${normalizedOwner}`,
    `vault_state_hash=${header.vault_state_hash}`,
  ].join("\n");
  const saltHash = await sha256Bytes(utf8(saltInput));
  const ikmInput = [
    "qave-recovery-unlock:v1",
    `signature_hash=${bytesToHex(signatureHash)}`,
    `challenge_hash=${bytesToHex(challengeHash)}`,
    `vault_owner=${normalizedOwner}`,
    `map_id=${header.map_id}`,
    `vault_state_hash=${header.vault_state_hash}`,
  ].join("\n");
  const ikmHash = await sha256Bytes(utf8(ikmInput));
  return deriveHKDF(ikmHash, saltHash, utf8(unlockKDFInfo));
}

async function deriveSessionExportSeed(sessionChallenge, signatureHex, walletAddress) {
  const signatureBytes = decodePersonalSignature(signatureHex);
  const normalizedWallet = normalizeWalletAddress(walletAddress);
  const sessionChallengeHash = await sha256Bytes(utf8(sessionChallenge));
  const signatureHash = await sha256Bytes(signatureBytes);
  const saltInput = [
    sessionChallengeVersionLine,
    `wallet=${normalizedWallet}`,
  ].join("\n");
  const saltHash = await sha256Bytes(utf8(saltInput));
  const ikmInput = [
    "qave-recovery-export-session-seed:v1",
    `signature_hash=${bytesToHex(signatureHash)}`,
    `session_challenge_hash=${bytesToHex(sessionChallengeHash)}`,
    `wallet=${normalizedWallet}`,
  ].join("\n");
  const ikmHash = await sha256Bytes(utf8(ikmInput));
  return deriveHKDF(ikmHash, saltHash, utf8(sessionSeedKDFInfo));
}

async function derivePayloadKeyFromSessionSeed(doc, sessionSeed) {
  const header = doc.header;
  const normalizedOwner = normalizeWalletAddress(header.vault_owner);
  const sessionSeedHash = await sha256Bytes(sessionSeed);
  const saltInput = [
    "qave-recovery-session-bound:v1",
    `map_id=${header.map_id}`,
    `vault_owner=${normalizedOwner}`,
    `vault_state_hash=${header.vault_state_hash}`,
    `nonce=${header.payload_encryption.nonce}`,
  ].join("\n");
  const saltHash = await sha256Bytes(utf8(saltInput));
  const ikmInput = [
    "qave-recovery-session-bound-payload-key:v1",
    `session_seed_hash=${bytesToHex(sessionSeedHash)}`,
    `map_id=${header.map_id}`,
    `vault_owner=${normalizedOwner}`,
    `vault_state_hash=${header.vault_state_hash}`,
    `nonce=${header.payload_encryption.nonce}`,
  ].join("\n");
  const ikmHash = await sha256Bytes(utf8(ikmInput));
  return deriveHKDF(ikmHash, saltHash, utf8(unlockKDFInfo));
}

async function decryptPayload(doc, key, manifestAAD) {
  const ciphertext = decodeBase64(doc.payload_ciphertext);
  const tag = decodeBase64(doc.payload_tag);
  const nonce = decodeBase64(doc.header.payload_encryption.nonce);
  const sealed = concatBytes(ciphertext, tag);
  let plaintext;
  try {
    plaintext = await aesGCMDecrypt(key, nonce, sealed, manifestAAD);
  } catch {
    fail("QRM_HEADER_PAYLOAD_MISMATCH", "payload could not be decrypted with signed manifest binding");
  } finally {
    zeroBytes(sealed);
  }

  try {
    return JSON.parse(textDecoder.decode(plaintext));
  } catch {
    fail("QRM_CORRUPTED", "decrypted payload is not valid json");
  } finally {
    zeroBytes(plaintext);
  }
}

export function validateRecoveryPayloadBinding(doc, payload, now = new Date()) {
  const snapshot = payload?.snapshot;
  if (!isPlainObject(snapshot)) {
    fail("QRM_HEADER_PAYLOAD_MISMATCH", "payload snapshot is missing");
  }
  const signature = validateSignatureShape(doc.header.qave_signature);
  if (`${snapshot.schema_version ?? ""}`.trim() !== recoveryPackageSchemaVersion) {
    fail("QRM_HEADER_PAYLOAD_MISMATCH", "payload snapshot schema_version does not match Recovery Package v1");
  }
  if (`${snapshot.package_id ?? ""}`.trim() !== `${doc.header.package_id ?? ""}`.trim()) {
    fail("QRM_HEADER_PAYLOAD_MISMATCH", "payload snapshot package_id does not match header");
  }
  if (`${snapshot.map_id ?? ""}`.trim() && `${snapshot.map_id ?? ""}`.trim() !== `${doc.header.map_id ?? ""}`.trim()) {
    fail("QRM_HEADER_PAYLOAD_MISMATCH", "payload snapshot map_id does not match header");
  }
  if (normalizeWalletAddress(snapshot.vault_owner) !== normalizeWalletAddress(doc.header.vault_owner)) {
    fail("QRM_OWNER_MISMATCH", "payload snapshot vault_owner does not match header");
  }
  if (`${snapshot.vault_state_hash ?? ""}`.trim() !== `${doc.header.vault_state_hash ?? ""}`.trim()) {
    fail("QRM_STATE_HASH_MISMATCH", "payload snapshot vault_state_hash does not match header");
  }
  if (`${snapshot.generated_at ?? ""}`.trim() !== `${doc.header.generated_at ?? ""}`.trim()) {
    fail("QRM_HEADER_PAYLOAD_MISMATCH", "payload snapshot generated_at does not match header");
  }
  if (`${snapshot.subscription_expires_at ?? ""}`.trim() !== `${doc.header.subscription_expires_at ?? ""}`.trim()) {
    fail("QRM_EXPIRY_MISMATCH", "payload snapshot subscription_expires_at does not match header");
  }
  if (`${snapshot.recovery_flow_version ?? ""}`.trim() !== signature.recovery_flow_version) {
    fail("QRM_HEADER_PAYLOAD_MISMATCH", "payload snapshot recovery_flow_version does not match signature");
  }
  const fileIndex = Array.isArray(payload.file_index) ? payload.file_index : [];
  if (Number(snapshot.file_count ?? -1) !== signature.file_count || signature.file_count !== fileIndex.length) {
    fail("QRM_HEADER_PAYLOAD_MISMATCH", "payload snapshot file_count does not match signature");
  }
  const packageExpiresAt = parseQRMTime(doc.header.subscription_expires_at, "subscription_expires_at");
  assertPackageNotExpired(packageExpiresAt, now);
  for (const file of fileIndex) {
    validateRecoveryFileNotBeyondPackage(file, packageExpiresAt);
  }
  return true;
}

export function validateTargetFileReady(doc, file, now = new Date()) {
  const packageExpiresAt = parseQRMTime(doc.header.subscription_expires_at, "subscription_expires_at");
  assertPackageNotExpired(packageExpiresAt, now);
  validateRecoveryFileNotBeyondPackage(file, packageExpiresAt);
  const fileExpiresAt = parseQRMTime(file?.expires_at, "file expires_at");
  if (fileExpiresAt.getTime() <= toDate(now).getTime()) {
    fail("QRM_EXPIRED", "target file recovery window has expired");
  }
  return true;
}

function validateRecoveryFileNotBeyondPackage(file, packageExpiresAt) {
  const fileExpiresAt = parseQRMTime(file?.expires_at, "file expires_at");
  if (fileExpiresAt.getTime() > packageExpiresAt.getTime()) {
    fail("QRM_EXPIRY_MISMATCH", "file expires_at is after package subscription_expires_at");
  }
}

export function selectFileByIndex(payload, index) {
  const files = Array.isArray(payload?.file_index) ? payload.file_index : [];
  const numericIndex = Number(index);
  if (!Number.isInteger(numericIndex) || numericIndex < 0 || numericIndex >= files.length) {
    fail("FILE_NOT_FOUND_IN_MAP", "file index is outside the qrm file list");
  }
  return files[numericIndex];
}

export function actionPermissions(state) {
  const packageVerified = state?.packageVerified === true;
  const payloadReady = packageVerified && state?.payloadUnlocked === true && state?.payloadConsistent === true;
  const targetReady = payloadReady && state?.targetFileValid === true;
  const ciphertextReady = targetReady && state?.ciphertextReady === true;
  const recoveryKeyReady = ciphertextReady && state?.recoveryKeyReady === true;
  return {
    walletUnlock: packageVerified,
    encryptedFileDownload: targetReady,
    copyEncryptedFileURL: targetReady,
    manualCiphertextUpload: targetReady,
    recoveryKeyInput: ciphertextReady,
    decrypt: recoveryKeyReady,
  };
}

export function queueActionPermissions(state) {
  const packageVerified = state?.packageVerified === true;
  const payloadReady = packageVerified && state?.payloadUnlocked === true && state?.payloadConsistent === true;
  const selectedValidCount = Number(state?.selectedValidCount ?? 0);
  const queueActive = state?.queueActive === true;
  const queueFinished = state?.queueFinished === true;
  const currentReady = payloadReady && queueActive && !queueFinished && state?.currentFileValid === true;
  const ciphertextReady = currentReady && state?.ciphertextReady === true;
  const recoveryKeyReady = currentReady && state?.recoveryKeyReady === true;
  const currentItemComplete = currentReady && state?.currentItemComplete === true;
  const hasNext = state?.hasNext === true;
  return {
    fileSelection: payloadReady && !queueActive,
    startQueue: payloadReady && !queueActive && selectedValidCount > 0,
    currentEncryptedFileDownload: currentReady,
    copyEncryptedFileURL: currentReady,
    currentManualCiphertextUpload: currentReady,
    currentRecoveryKeyInput: currentReady,
    currentDecrypt: ciphertextReady && recoveryKeyReady,
    skipCurrentFile: currentReady,
    continueToNext: currentItemComplete && hasNext,
    finishQueue: currentItemComplete && !hasNext,
    recoverAnotherSelection: queueFinished,
  };
}

export function listRecoverableFiles(doc, payload, options = {}) {
  const files = Array.isArray(payload?.file_index) ? payload.file_index : [];
  return files.map((file, index) => {
    try {
      validateTargetFileReady(doc, file, options.now);
      return {
        index,
        file,
        recoverable: true,
        code: "READY",
        message: "Ready to recover",
        hasSafeCiphertextURL: selectCiphertextDownloadSource(payload, file) !== null,
      };
    } catch (error) {
      return {
        index,
        file,
        recoverable: false,
        code: error instanceof RecoveryToolError ? error.code : "RECOVERY_TOOL_ERROR",
        message: safeErrorMessage(error),
        hasSafeCiphertextURL: false,
      };
    }
  });
}

export function createRecoveryQueue(fileRows, selectedIndexes) {
  const selected = new Set(Array.from(selectedIndexes ?? [], (value) => Number(value)));
  const items = (Array.isArray(fileRows) ? fileRows : [])
    .filter((row) => row?.recoverable === true && selected.has(Number(row.index)))
    .map((row, queueIndex) => ({
      queueIndex,
      index: row.index,
      file: row.file,
      status: queueIndex === 0 ? "current" : "waiting",
      message: queueIndex === 0 ? "Current" : "Waiting",
    }));
  return {
    items,
    currentPosition: items.length > 0 ? 0 : -1,
  };
}

export function getQueueCurrentItem(queue) {
  const position = Number(queue?.currentPosition ?? -1);
  if (!Array.isArray(queue?.items) || position < 0 || position >= queue.items.length) {
    return null;
  }
  return queue.items[position];
}

export function markQueueCurrentItem(queue, status, message = "") {
  const current = getQueueCurrentItem(queue);
  if (!current) return cloneQueue(queue);
  const next = cloneQueue(queue);
  next.items[current.queueIndex] = {
    ...next.items[current.queueIndex],
    status: `${status ?? ""}`.trim() || current.status,
    message: `${message ?? ""}`.trim() || statusLabel(status),
  };
  return next;
}

export function advanceRecoveryQueue(queue) {
  const next = cloneQueue(queue);
  const currentPosition = Number(next.currentPosition ?? -1);
  for (let index = currentPosition + 1; index < next.items.length; index += 1) {
    if (next.items[index].status === "waiting") {
      next.items[index] = {
        ...next.items[index],
        status: "current",
        message: "Current",
      };
      next.currentPosition = index;
      return next;
    }
  }
  next.currentPosition = -1;
  return next;
}

export function queueStatusCounts(queue) {
  const items = Array.isArray(queue?.items) ? queue.items : [];
  const counts = {
    total: items.length,
    waiting: 0,
    current: 0,
    uploaded: 0,
    recovered: 0,
    failed: 0,
    skipped: 0,
    finished: items.length > 0 && Number(queue?.currentPosition ?? -1) === -1,
  };
  for (const item of items) {
    if (Object.prototype.hasOwnProperty.call(counts, item.status)) {
      counts[item.status] += 1;
    }
  }
  return counts;
}

export function resetCurrentFileTransientState(transient, options = {}) {
  const preserveRecoveryKey = options.preserveRecoveryKey !== false;
  return {
    ciphertextReady: false,
    recoveryKeyReady: preserveRecoveryKey && transient?.recoveryKeyReady === true,
    plaintextReady: false,
  };
}

function cloneQueue(queue) {
  return {
    items: (Array.isArray(queue?.items) ? queue.items : []).map((item) => ({ ...item })),
    currentPosition: Number(queue?.currentPosition ?? -1),
  };
}

function statusLabel(status) {
  switch (`${status ?? ""}`.trim()) {
    case "waiting":
      return "Waiting";
    case "current":
      return "Current";
    case "uploaded":
      return "Encrypted file uploaded";
    case "recovered":
      return "Recovered";
    case "failed":
      return "Failed";
    case "skipped":
      return "Skipped";
    default:
      return "Updated";
  }
}

export function selectCiphertextDownloadSource(payload, file) {
  const candidates = resolveCiphertextDownloadCandidates(payload, file);
  return candidates.length > 0 ? candidates[0] : null;
}

export function resolveCiphertextDownloadCandidates(payload, file) {
  const fileID = `${file?.file_id ?? ""}`.trim();
  const candidates = [];
  if (fileID) {
    for (const source of Array.isArray(payload?.fetch_sources) ? payload.fetch_sources : []) {
      if (`${source?.file_id ?? ""}`.trim() !== fileID) continue;
      pushDownloadCandidate(candidates, source?.source_type, source?.source_ref);
      pushDownloadCandidate(candidates, source?.source_type || "cid", source?.cid);
    }
  }
  for (const ref of Array.isArray(file?.storage_refs) ? file.storage_refs : []) {
    pushDownloadCandidate(candidates, ref?.kind, ref?.value);
  }
  pushDownloadCandidate(candidates, "cid", file?.cid);

  const seen = new Set();
  return candidates.filter((candidate) => {
    const key = candidate.url;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function pushDownloadCandidate(candidates, kind, rawURL) {
  const normalized = normalizeRecoveryPieceGatewayURL(`${rawURL ?? ""}`.trim());
  if (!normalized) return;
  try {
    const safeURL = validateCiphertextDownloadURL(normalized);
    candidates.push({ kind: `${kind ?? "url"}`.trim() || "url", url: safeURL });
  } catch {
    // Unsafe or non-URL references stay unavailable in the browser tool.
  }
}

export function validateCiphertextDownloadURL(rawURL) {
  let url;
  try {
    url = new URL(`${rawURL ?? ""}`.trim());
  } catch {
    fail("UNSUPPORTED_CIPHERTEXT_SOURCE", "encrypted file URL is invalid");
  }
  if (url.protocol !== "https:") {
    fail("UNSUPPORTED_CIPHERTEXT_SOURCE", "encrypted file URL must use https");
  }
  if (url.username || url.password) {
    fail("UNSUPPORTED_CIPHERTEXT_SOURCE", "encrypted file URL must not include credentials");
  }
  const hostname = normalizeURLHostname(url.hostname);
  if (!hostname) {
    fail("UNSUPPORTED_CIPHERTEXT_SOURCE", "encrypted file URL host is missing");
  }
  if (isBlockedLocalHostname(hostname) || isBlockedIPAddress(hostname)) {
    fail("UNSUPPORTED_CIPHERTEXT_SOURCE", "encrypted file URL host is private or local");
  }
  return url.toString();
}

export async function decryptSelectedFile(payload, file, ciphertextBytes, recoveryKey) {
  validateCiphertextBytes(ciphertextBytes);
  const wrappedKey = selectWrappedKeyByFileID(payload, file?.file_id);
  const profile = selectRecoveryProfile(payload, file, wrappedKey);
  const wrapKey = await deriveRecoveryWrapKeyBytes(recoveryKey, profile);
  try {
    const fileKey = await unwrapRecoveryFileKey(wrapKey, wrappedKey);
    try {
      return await decryptLocalCiphertextFromBytes(ciphertextBytes, file, fileKey);
    } finally {
      zeroBytes(fileKey);
    }
  } finally {
    zeroBytes(wrapKey);
  }
}

function selectWrappedKeyByFileID(payload, fileID) {
  const target = `${fileID ?? ""}`.trim();
  const matches = (Array.isArray(payload?.wrapped_keys) ? payload.wrapped_keys : []).filter(
    (wrappedKey) => `${wrappedKey?.file_id ?? ""}`.trim() === target,
  );
  if (matches.length === 0) {
    fail("WRAPPED_KEY_NOT_FOUND", "wrapped key entry was not found for file_id");
  }
  if (matches.length > 1) {
    fail("QRM_CORRUPTED", "wrapped key entry is not unique for file_id");
  }
  return matches[0];
}

function selectRecoveryProfile(payload, file, wrappedKey) {
  const targetVersion = Number(wrappedKey?.recovery_material_version ?? 0);
  if (!Number.isInteger(targetVersion) || targetVersion <= 0) {
    fail("RECOVERY_PROFILE_NOT_FOUND", "wrapped key is missing recovery_material_version");
  }
  if (file?.recovery_material_version != null && Number(file.recovery_material_version) !== targetVersion) {
    fail("QRM_CORRUPTED", "file recovery_material_version does not match wrapped key");
  }
  const profiles = Array.isArray(payload?.snapshot?.recovery_kdf_profiles)
    ? payload.snapshot.recovery_kdf_profiles
    : [];
  const matches = profiles.filter((profile) => Number(profile?.material_version ?? 0) === targetVersion);
  if (matches.length === 0) {
    fail("RECOVERY_PROFILE_NOT_FOUND", "recovery profile was not found for material_version");
  }
  if (matches.length > 1) {
    fail("QRM_CORRUPTED", "recovery profile is not unique for material_version");
  }
  return matches[0];
}

async function deriveRecoveryWrapKeyBytes(recoveryKey, profile) {
  if (`${profile?.kdf_algorithm ?? ""}`.trim() !== recoveryKDFAlgorithmPBKDF2SHA256) {
    fail("UNSUPPORTED_RECOVERY_CRYPTO", "unsupported recovery kdf algorithm");
  }
  if (Number(profile?.kdf_version ?? 0) !== recoveryKDFVersion1) {
    fail("UNSUPPORTED_RECOVERY_CRYPTO", "unsupported recovery kdf version");
  }
  if (`${profile?.kdf_params?.hash ?? ""}`.trim() !== recoveryKDFHashSHA256) {
    fail("UNSUPPORTED_RECOVERY_CRYPTO", "unsupported recovery kdf hash");
  }
  if (Number(profile?.kdf_params?.derived_key_length ?? 0) !== recoveryDerivedKeyLengthBytes) {
    fail("UNSUPPORTED_RECOVERY_CRYPTO", "unsupported recovery kdf length");
  }
  const iterations = Number(profile?.kdf_params?.iterations ?? 0);
  if (!Number.isInteger(iterations) || iterations <= 0) {
    fail("QRM_CORRUPTED", "recovery kdf iterations must be positive");
  }

  const normalizedRecoveryKey = parseRecoveryKeyMaterial(recoveryKey);
  const passwordBytes = utf8(normalizedRecoveryKey);
  const saltBytes = decodeBase64(`${profile?.kdf_salt ?? ""}`.trim());
  try {
    const key = await crypto.subtle.importKey("raw", passwordBytes, "PBKDF2", false, ["deriveBits"]);
    const bits = await crypto.subtle.deriveBits(
      {
        name: "PBKDF2",
        hash: "SHA-256",
        salt: toArrayBuffer(saltBytes),
        iterations,
      },
      key,
      recoveryDerivedKeyLengthBytes * 8,
    );
    return new Uint8Array(bits);
  } finally {
    zeroBytes(passwordBytes);
    zeroBytes(saltBytes);
  }
}

async function unwrapRecoveryFileKey(wrapKey, wrappedKey) {
  if (`${wrappedKey?.wrapped_file_key ?? ""}`.trim() === "") {
    fail("WRAPPED_KEY_NOT_FOUND", "wrapped_file_key is missing for file_id");
  }
  if (`${wrappedKey?.key_wrap_algorithm ?? ""}`.trim() !== recoveryWrapAlgorithmAES256GCM) {
    fail("UNSUPPORTED_RECOVERY_CRYPTO", "unsupported wrapped key algorithm");
  }
  if (Number(wrappedKey?.key_wrap_version ?? 0) !== recoveryWrapVersion1) {
    fail("UNSUPPORTED_RECOVERY_CRYPTO", "unsupported wrapped key version");
  }
  if (Number(wrappedKey?.key_material_version ?? 0) !== recoveryKeyMaterialVersion1) {
    fail("UNSUPPORTED_RECOVERY_CRYPTO", "unsupported key material version");
  }
  if (`${wrappedKey?.iv ?? ""}`.trim() === "") {
    fail("WRAPPED_KEY_NOT_FOUND", "wrapped key iv is missing for file_id");
  }
  if (`${wrappedKey?.nonce ?? ""}`.trim() || `${wrappedKey?.aad ?? ""}`.trim() || `${wrappedKey?.tag ?? ""}`.trim()) {
    fail("UNSUPPORTED_RECOVERY_CRYPTO", "wrapped key auxiliary nonce/aad/tag fields are not supported in this build");
  }

  const sealedBytes = decodeBase64(`${wrappedKey.wrapped_file_key}`.trim());
  const ivBytes = decodeBase64(`${wrappedKey.iv}`.trim());
  try {
    if (sealedBytes.length !== wrappedFileKeyLengthBytes) {
      fail("QRM_CORRUPTED", "wrapped_file_key length is invalid");
    }
    if (ivBytes.length !== wrapIVLengthBytes) {
      fail("QRM_CORRUPTED", "wrapped key iv length is invalid");
    }
    const fileKey = await aesGCMDecrypt(wrapKey, ivBytes, sealedBytes, null);
    if (fileKey.length !== fileKeyLengthBytes) {
      zeroBytes(fileKey);
      fail("QRM_CORRUPTED", "unwrapped file key length is invalid");
    }
    return fileKey;
  } catch (error) {
    if (error instanceof RecoveryToolError) throw error;
    fail("RECOVERY_KEY_INVALID", "recovery key could not unwrap file key");
  } finally {
    zeroBytes(sealedBytes);
    zeroBytes(ivBytes);
  }
}

async function decryptLocalCiphertextFromBytes(ciphertextBytes, file, fileKeyBytes) {
  if (!isPlainObject(file?.content_encryption)) {
    fail("CONTENT_ENCRYPTION_METADATA_MISSING", "content_encryption metadata is missing for file_id");
  }
  if (Number(file.content_encryption.encryption_version ?? 0) !== 1) {
    fail("UNSUPPORTED_RECOVERY_CRYPTO", "unsupported content encryption version");
  }
  if (`${file.content_encryption.content_encryption_algorithm ?? ""}`.trim() !== recoveryWrapAlgorithmAES256GCM) {
    fail("UNSUPPORTED_RECOVERY_CRYPTO", "unsupported content encryption algorithm");
  }

  const ivBytes = decodeBase64(`${file.content_encryption.content_encryption_iv ?? ""}`.trim());
  try {
    if (ivBytes.length !== wrapIVLengthBytes) {
      fail("QRM_CORRUPTED", "content_encryption_iv length is invalid");
    }
    const input = new Uint8Array(ciphertextBytes);
    if (input.length <= aesGCMTagLength) {
      zeroBytes(input);
      fail("QRM_CORRUPTED", "ciphertext is shorter than AES-GCM tag length");
    }
    const plaintext = await aesGCMDecrypt(fileKeyBytes, ivBytes, input, null);
    const expectedSize = Number(file?.size ?? 0);
    if (expectedSize > 0 && plaintext.length !== expectedSize) {
      zeroBytes(plaintext);
      fail("PLAINTEXT_SIZE_MISMATCH", "decrypted plaintext size does not match qrm file size");
    }
    return plaintext;
  } catch (error) {
    if (error instanceof RecoveryToolError) throw error;
    fail("CIPHERTEXT_DECRYPT_FAILED", "ciphertext could not be decrypted with the resolved file key");
  } finally {
    zeroBytes(ivBytes);
  }
}

function validateCiphertextBytes(ciphertextBytes) {
  if (!(ciphertextBytes instanceof Uint8Array) || ciphertextBytes.length <= aesGCMTagLength) {
    fail("QRM_CORRUPTED", "ciphertext is shorter than AES-GCM tag length");
  }
}

export function parseRecoveryKeyMaterial(value) {
  const trimmed = `${value ?? ""}`.trim();
  if (!trimmed) {
    fail("RECOVERY_KEY_MISSING", "recovery key is required");
  }
  let normalized = "";
  for (const char of trimmed.toUpperCase()) {
    if (char === "-" || /\s/.test(char)) {
      continue;
    }
    if (!recoveryKeyAlphabet.includes(char)) {
      fail(
        "RECOVERY_KEY_INVALID_FORMAT",
        "recovery key contains invalid characters; only letters A-Z without I/L/O and digits 2-9 are allowed",
      );
    }
    normalized += char;
  }
  if (!normalized) {
    fail("RECOVERY_KEY_MISSING", "recovery key is required");
  }
  if (normalized.length !== recoveryKeyRawLength) {
    fail("RECOVERY_KEY_INVALID_LENGTH", `recovery key must be ${recoveryKeyRawLength} characters after removing spaces and hyphens`);
  }
  return normalized;
}

export function safeDownloadName(file, fallbackIndex = 0) {
  const raw = `${file?.name || file?.file_name || `recovered-file-${fallbackIndex + 1}`}`.trim();
  const parts = raw.split(/[\\/]+/).filter(Boolean);
  const name = parts[parts.length - 1] || `recovered-file-${fallbackIndex + 1}`;
  const cleaned = name.replace(/[<>:"|?*\u0000-\u001f]+/g, "_").replace(/^\.+$/, "_");
  return cleaned || `recovered-file-${fallbackIndex + 1}`;
}

export function normalizeWalletAddress(value) {
  const trimmed = `${value ?? ""}`.trim();
  if (!/^0x[0-9a-fA-F]{40}$/.test(trimmed)) {
    fail("WALLET_ADDRESS_INVALID", "wallet address must be a 20-byte hex address");
  }
  return trimmed.toLowerCase();
}

export function personalSignMessageHex(message) {
  return "0x" + bytesToHex(utf8(message));
}

function decodePersonalSignature(signatureHex) {
  const bytes = decodeHexToBytes(`${signatureHex ?? ""}`.trim().replace(/^0x/i, ""));
  if (bytes.length !== 65) {
    fail("SIGNATURE_INVALID", "signature must be 65 bytes");
  }
  if (bytes[64] !== 0 && bytes[64] !== 1 && bytes[64] !== 27 && bytes[64] !== 28) {
    fail("SIGNATURE_INVALID", "signature recovery id must be 27/28 or 0/1");
  }
  return bytes;
}

function parseQRMTime(value, label) {
  const raw = `${value ?? ""}`.trim();
  const millis = Date.parse(raw);
  if (!raw || Number.isNaN(millis)) {
    fail("QRM_CORRUPTED", `${label} must be valid ISO8601`);
  }
  return new Date(millis);
}

function assertPackageNotExpired(expiresAt, now = new Date()) {
  if (expiresAt.getTime() <= toDate(now).getTime()) {
    fail("QRM_EXPIRED", "qrm subscription window has expired");
  }
}

function toDate(value) {
  if (value instanceof Date) return value;
  return new Date(value);
}

async function verifyEd25519(publicKeyBytes, signatureBytes, messageBytes) {
  const key = await crypto.subtle.importKey(
    "raw",
    toArrayBuffer(publicKeyBytes),
    { name: "Ed25519" },
    false,
    ["verify"],
  );
  return crypto.subtle.verify(
    { name: "Ed25519" },
    key,
    toArrayBuffer(signatureBytes),
    toArrayBuffer(messageBytes),
  );
}

function isEd25519Unsupported(error) {
  return (
    error?.name === "NotSupportedError" ||
    error?.name === "NotFoundError" ||
    /Ed25519|algorithm|not supported|unrecognized/i.test(`${error?.message ?? ""}`)
  );
}

async function deriveHKDF(ikmHash, saltHash, info) {
  const hkdfKey = await crypto.subtle.importKey("raw", toArrayBuffer(ikmHash), "HKDF", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: toArrayBuffer(saltHash),
      info: toArrayBuffer(info),
    },
    hkdfKey,
    256,
  );
  return new Uint8Array(bits);
}

async function aesGCMDecrypt(keyBytes, ivBytes, sealedBytes, aadBytes) {
  const key = await crypto.subtle.importKey("raw", toArrayBuffer(keyBytes), { name: "AES-GCM" }, false, ["decrypt"]);
  const params = {
    name: "AES-GCM",
    iv: toArrayBuffer(ivBytes),
    tagLength: 128,
  };
  if (aadBytes instanceof Uint8Array) {
    params.additionalData = toArrayBuffer(aadBytes);
  }
  return new Uint8Array(await crypto.subtle.decrypt(params, key, toArrayBuffer(sealedBytes)));
}

export async function sha256Bytes(input) {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", toArrayBuffer(input)));
}

export async function sha256Hex(input) {
  return bytesToHex(await sha256Bytes(input));
}

export function decodeHexToBytes(value) {
  const normalized = `${value ?? ""}`.trim().toLowerCase();
  if (!/^[0-9a-f]*$/.test(normalized) || normalized.length % 2 !== 0) {
    fail("INVALID_HEX", "hex value is invalid");
  }
  const bytes = new Uint8Array(normalized.length / 2);
  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = Number.parseInt(normalized.slice(index * 2, index * 2 + 2), 16);
  }
  return bytes;
}

export function decodeBase64(value) {
  const raw = `${value ?? ""}`.trim();
  if (!raw) {
    fail("INVALID_BASE64", "base64 value is empty");
  }
  if (typeof globalThis.atob === "function") {
    try {
      const binary = globalThis.atob(raw);
      const bytes = new Uint8Array(binary.length);
      for (let index = 0; index < binary.length; index += 1) {
        bytes[index] = binary.charCodeAt(index);
      }
      return bytes;
    } catch {
      fail("INVALID_BASE64", "base64 value is invalid");
    }
  }
  if (typeof Buffer !== "undefined") {
    return new Uint8Array(Buffer.from(raw, "base64"));
  }
  fail("INVALID_BASE64", "base64 decoder is unavailable");
}

export function encodeBase64(bytes) {
  if (typeof globalThis.btoa === "function") {
    let binary = "";
    for (const byte of bytes) {
      binary += String.fromCharCode(byte);
    }
    return globalThis.btoa(binary);
  }
  if (typeof Buffer !== "undefined") {
    return Buffer.from(bytes).toString("base64");
  }
  fail("INVALID_BASE64", "base64 encoder is unavailable");
}

export function utf8(value) {
  return textEncoder.encode(value);
}

export function bytesToHex(bytes) {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function concatBytes(left, right) {
  const out = new Uint8Array(left.length + right.length);
  out.set(left, 0);
  out.set(right, left.length);
  return out;
}

function toArrayBuffer(value) {
  return value.buffer.slice(value.byteOffset, value.byteOffset + value.byteLength);
}

export function zeroBytes(value) {
  if (value instanceof Uint8Array) {
    value.fill(0);
  }
}

function sortRecursively(value) {
  if (Array.isArray(value)) {
    return value.map(sortRecursively);
  }
  if (isPlainObject(value)) {
    return Object.keys(value)
      .sort()
      .reduce((acc, key) => {
        acc[key] = sortRecursively(value[key]);
        return acc;
      }, {});
  }
  return value;
}

function isPlainObject(value) {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function normalizeRecoveryPieceGatewayURL(raw) {
  const trimmed = `${raw ?? ""}`.trim();
  if (!trimmed) return "";
  let parsed;
  try {
    parsed = new URL(trimmed);
  } catch {
    return trimmed;
  }
  if (parsed.hostname.toLowerCase() !== recoveryPieceHostTypo) {
    return trimmed;
  }
  parsed.hostname = recoveryPieceHostCanonical;
  return parsed.toString();
}

function normalizeURLHostname(hostname) {
  return `${hostname ?? ""}`.trim().toLowerCase().replace(/^\[|\]$/g, "");
}

function isBlockedLocalHostname(hostname) {
  return (
    hostname === "localhost" ||
    hostname.endsWith(".localhost") ||
    hostname === "localhost.localdomain"
  );
}

function isBlockedIPAddress(hostname) {
  if (isBlockedIPv4(hostname)) return true;
  if (hostname.startsWith("::ffff:")) {
    return isBlockedIPv4(hostname.slice("::ffff:".length));
  }
  return isBlockedIPv6(hostname);
}

function isBlockedIPv4(hostname) {
  if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)) return false;
  const parts = hostname.split(".").map((part) => Number(part));
  if (parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) {
    return true;
  }
  const [a, b] = parts;
  return (
    a === 0 ||
    a === 10 ||
    a === 127 ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    (a === 100 && b >= 64 && b <= 127) ||
    (a === 198 && (b === 18 || b === 19)) ||
    a >= 224
  );
}

function isBlockedIPv6(hostname) {
  const h = hostname.toLowerCase();
  if (!h.includes(":")) return false;
  return (
    h === "::1" ||
    h === "0:0:0:0:0:0:0:1" ||
    h.startsWith("fe80:") ||
    h.startsWith("fc") ||
    h.startsWith("fd")
  );
}
