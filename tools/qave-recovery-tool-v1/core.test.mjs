import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import { readFile } from "node:fs/promises";
import { test } from "node:test";

import {
  actionPermissions,
  advanceRecoveryQueue,
  canonicalRecoverySignedManifestJSON,
  createRecoveryQueue,
  decodeBase64,
  encodeBase64,
  evaluateQRMForUnlock,
  getQueueCurrentItem,
  listRecoverableFiles,
  markQueueCurrentItem,
  qaveRecoveryPublicKeyFingerprint16,
  qaveRecoveryPublicKeySHA256Hex,
  qaveRecoveryPublicKeyBase64,
  queueActionPermissions,
  recoveryFlowVersion,
  recoverySignedManifestHashHex,
  resetCurrentFileTransientState,
  resolveCiphertextDownloadCandidates,
  selectCiphertextDownloadSource,
  sha256Hex,
  unlockPayloadWithSignature,
  utf8,
  validateCiphertextDownloadURL,
  validateQRMForUnlock,
  validateTargetFileReady,
} from "./core.mjs";

if (!globalThis.crypto) {
  globalThis.crypto = webcrypto;
}

const now = new Date("2026-03-24T20:31:55Z");
const future = "2026-03-25T20:31:55Z";
const owner = "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd";

test("canonical signed manifest matches frontend and CLI rules", async () => {
  const header = sampleHeader({ subscription_expires_at: future });
  const canonical = canonicalRecoverySignedManifestJSON(header, 2, recoveryFlowVersion);
  assert.equal(
    canonical,
    '{"file_count":2,"generated_at":"2026-03-24T20:31:55Z","map_id":"map-123","package_id":"package-123","payload_encryption":{"algorithm":"AES-256-GCM","binding":"wallet_personal_sign_v1","kdf":"HKDF-SHA-256","nonce":"base64-nonce"},"recovery_flow_version":"recover-all.v1","schema":"qave.recovery-map.v1","subscription_expires_at":"2026-03-25T20:31:55Z","vault_owner":"0xabcdefabcdefabcdefabcdefabcdefabcdefabcd","vault_state_hash":"vault-state-hash"}',
  );
  assert.equal(await recoverySignedManifestHashHex(header, 2, recoveryFlowVersion), "af4752254354229af0f5a33748ac51a10f5d34de1f42f1fde153d15a4da0761c");
});

test("Qave public key fingerprint matches launch key", async () => {
  assert.equal(await sha256Hex(decodeBase64(qaveRecoveryPublicKeyBase64)), qaveRecoveryPublicKeySHA256Hex);
  assert.equal(qaveRecoveryPublicKeySHA256Hex.slice(0, 16), qaveRecoveryPublicKeyFingerprint16);
});

test("valid signed package reaches wallet gate with injected test key", async () => {
  const fixture = await signedFixture({ expiresAt: future });
  const gate = await validateQRMForUnlock(fixture.doc, {
    now,
    publicKeys: { "qave-recovery-2026-v1": fixture.publicKey },
  });
  assert.equal(gate.signature.key_id, "qave-recovery-2026-v1");
  assert.equal(actionPermissions({ packageVerified: true }).walletUnlock, true);
});

test("expired package is rejected before wallet, fetch, or decrypt actions", async () => {
  const fixture = await signedFixture({ expiresAt: "2026-03-24T20:31:55Z" });
  const evaluated = await evaluateQRMForUnlock(fixture.doc, {
    now,
    publicKeys: { "qave-recovery-2026-v1": fixture.publicKey },
  });
  assert.equal(evaluated.ok, false);
  assert.equal(evaluated.code, "QRM_EXPIRED");
  assert.deepEqual(evaluated.actions, {
    walletUnlock: false,
    encryptedFileDownload: false,
    copyEncryptedFileURL: false,
    manualCiphertextUpload: false,
    recoveryKeyInput: false,
    decrypt: false,
  });
});

test("tampered expiry package_id and nonce fail closed", async () => {
  const fixture = await signedFixture({ expiresAt: future });
  for (const mutate of [
    (doc) => {
      doc.header.subscription_expires_at = "2026-03-26T20:31:55Z";
    },
    (doc) => {
      doc.header.package_id = "package-tampered";
    },
    (doc) => {
      doc.header.payload_encryption.nonce = encodeBase64(new Uint8Array(12).fill(9));
    },
  ]) {
    const doc = structuredClone(fixture.doc);
    mutate(doc);
    const evaluated = await evaluateQRMForUnlock(doc, {
      now,
      publicKeys: { "qave-recovery-2026-v1": fixture.publicKey },
    });
    assert.equal(evaluated.ok, false);
    assert.equal(evaluated.actions.walletUnlock, false);
    assert.equal(evaluated.actions.manualCiphertextUpload, false);
  }
});

test("manual ciphertext fallback cannot bypass expiry or signature gates", async () => {
  assert.equal(actionPermissions({}).manualCiphertextUpload, false);
  assert.equal(actionPermissions({}).encryptedFileDownload, false);
  assert.equal(
    actionPermissions({
      packageVerified: false,
      payloadUnlocked: true,
      payloadConsistent: true,
      targetFileValid: true,
    }).manualCiphertextUpload,
    false,
  );
  assert.equal(
    actionPermissions({
      packageVerified: false,
      payloadUnlocked: true,
      payloadConsistent: true,
      targetFileValid: true,
    }).encryptedFileDownload,
    false,
  );
  assert.equal(
    actionPermissions({
      packageVerified: true,
      payloadUnlocked: false,
      payloadConsistent: true,
      targetFileValid: true,
    }).manualCiphertextUpload,
    false,
  );
  assert.equal(
    actionPermissions({
      packageVerified: true,
      payloadUnlocked: false,
      payloadConsistent: true,
      targetFileValid: true,
    }).encryptedFileDownload,
    false,
  );
  assert.equal(
    actionPermissions({
      packageVerified: true,
      payloadUnlocked: true,
      payloadConsistent: true,
      targetFileValid: true,
    }).manualCiphertextUpload,
    true,
  );
  assert.equal(
    actionPermissions({
      packageVerified: true,
      payloadUnlocked: true,
      payloadConsistent: true,
      targetFileValid: true,
    }).encryptedFileDownload,
    true,
  );
});

test("ciphertext download URL allowlist permits https and blocks local/private targets", () => {
  assert.equal(validateCiphertextDownloadURL("https://provider.example/piece/bafy"), "https://provider.example/piece/bafy");
  assert.equal(validateCiphertextDownloadURL("https://fd-example.invalid/piece/bafy"), "https://fd-example.invalid/piece/bafy");
  for (const badURL of [
    "http://provider.example/piece/bafy",
    "file:///tmp/blob.enc",
    "javascript:alert(1)",
    "data:text/plain,abc",
    "https://localhost/piece/bafy",
    "https://127.0.0.1/piece/bafy",
    "https://10.0.0.8/piece/bafy",
    "https://172.16.0.1/piece/bafy",
    "https://172.31.255.255/piece/bafy",
    "https://192.168.1.5/piece/bafy",
    "https://[::1]/piece/bafy",
    "https://[fd00::1]/piece/bafy",
    "https://[fe80::1]/piece/bafy",
  ]) {
    assert.throws(() => validateCiphertextDownloadURL(badURL), /encrypted file URL/);
  }
});

test("valid target file extracts safe https ciphertext download URL", () => {
  const payload = {
    fetch_sources: [
      {
        file_id: "file-1",
        source_type: "retrieval_url",
        source_ref: "https://safe.example/piece/1",
      },
    ],
  };
  const file = {
    file_id: "file-1",
    cid: "",
    storage_refs: [],
  };
  assert.deepEqual(selectCiphertextDownloadSource(payload, file), {
    kind: "retrieval_url",
    url: "https://safe.example/piece/1",
  });
});

test("unsafe private and local URLs are not shown as downloadable ciphertext URLs", () => {
  const payload = {
    fetch_sources: [
      {
        file_id: "file-1",
        source_type: "retrieval_url",
        source_ref: "https://127.0.0.1/piece/1",
        cid: "javascript:alert(1)",
      },
    ],
  };
  const file = {
    file_id: "file-1",
    cid: "file:///tmp/ciphertext",
    storage_refs: [
      { kind: "provider_piece_url", value: "http://provider.example/piece/1" },
      { kind: "provider_piece_url", value: "https://127.0.0.1/piece/1" },
      { kind: "provider_piece_url", value: "https://10.0.0.4/piece/1" },
    ],
  };
  assert.equal(selectCiphertextDownloadSource(payload, file), null);
  assert.deepEqual(resolveCiphertextDownloadCandidates(payload, file), []);
});

test("signed header with mismatched payload AAD fails during payload unlock", async () => {
  const keyPair = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  const signatureHex = `0x${"11".repeat(64)}1b`;
  const fixtureA = await encryptedSignedFixture({
    keyPair,
    packageID: "package-a",
    signatureHex,
  });
  const fixtureB = await encryptedSignedFixture({
    keyPair,
    packageID: "package-b",
    signatureHex,
  });
  const stitched = {
    ...fixtureA.doc,
    payload_ciphertext: fixtureB.doc.payload_ciphertext,
    payload_tag: fixtureB.doc.payload_tag,
  };

  const gate = await validateQRMForUnlock(stitched, {
    now,
    publicKeys: { "qave-recovery-2026-v1": fixtureA.publicKey },
  });
  assert.equal(gate.signature.key_id, "qave-recovery-2026-v1");
  await assert.rejects(
    () => unlockPayloadWithSignature(stitched, signatureHex, owner, { gate, now }),
    (error) => error?.code === "QRM_HEADER_PAYLOAD_MISMATCH",
  );
  assert.equal(
    actionPermissions({
      packageVerified: true,
      payloadUnlocked: false,
      payloadConsistent: false,
      targetFileValid: true,
    }).manualCiphertextUpload,
    false,
  );
  assert.equal(
    actionPermissions({
      packageVerified: true,
      payloadUnlocked: false,
      payloadConsistent: false,
      targetFileValid: true,
      ciphertextReady: true,
      recoveryKeyReady: true,
    }).decrypt,
    false,
  );
});

test("target file expiry is rejected while package is still valid", () => {
  const doc = { header: sampleHeader({ subscription_expires_at: future }) };
  assert.throws(
    () => validateTargetFileReady(doc, { expires_at: "2026-03-24T20:31:55Z" }, now),
    (error) => error?.code === "QRM_EXPIRED",
  );
  assert.equal(
    actionPermissions({
      packageVerified: true,
      payloadUnlocked: true,
      payloadConsistent: true,
      targetFileValid: false,
      ciphertextReady: true,
      recoveryKeyReady: true,
    }).manualCiphertextUpload,
    false,
  );
  assert.equal(
    actionPermissions({
      packageVerified: true,
      payloadUnlocked: true,
      payloadConsistent: true,
      targetFileValid: false,
      ciphertextReady: true,
      recoveryKeyReady: true,
    }).encryptedFileDownload,
    false,
  );
  assert.equal(
    actionPermissions({
      packageVerified: true,
      payloadUnlocked: true,
      payloadConsistent: true,
      targetFileValid: false,
      ciphertextReady: true,
      recoveryKeyReady: true,
    }).copyEncryptedFileURL,
    false,
  );
  assert.equal(
    actionPermissions({
      packageVerified: true,
      payloadUnlocked: true,
      payloadConsistent: true,
      targetFileValid: false,
      ciphertextReady: true,
      recoveryKeyReady: true,
    }).decrypt,
    false,
  );
});

test("file expiry after package expiry is rejected as mismatch", () => {
  const doc = { header: sampleHeader({ subscription_expires_at: future }) };
  assert.throws(
    () => validateTargetFileReady(doc, { expires_at: "2026-03-26T20:31:55Z" }, now),
    (error) => error?.code === "QRM_EXPIRY_MISMATCH",
  );
});

test("multiple file_index entries can be filtered into recoverable queue rows", () => {
  const doc = { header: sampleHeader({ subscription_expires_at: future }) };
  const payload = {
    file_index: [
      queueFile("file-a", { name: "alpha.txt", expires_at: future }),
      queueFile("file-b", { name: "bravo.txt", expires_at: future }),
    ],
    fetch_sources: [
      { file_id: "file-a", source_type: "retrieval_url", source_ref: "https://safe.example/piece/a" },
      { file_id: "file-b", source_type: "retrieval_url", source_ref: "https://safe.example/piece/b" },
    ],
  };

  const rows = listRecoverableFiles(doc, payload, { now });
  assert.deepEqual(rows.map((row) => [row.index, row.recoverable, row.hasSafeCiphertextURL]), [
    [0, true, true],
    [1, true, true],
  ]);

  const queue = createRecoveryQueue(rows, new Set([0, 1]));
  assert.equal(queue.items.length, 2);
  assert.equal(getQueueCurrentItem(queue).index, 0);
  assert.equal(queue.items[1].status, "waiting");
});

test("expired target files cannot join the recovery queue", () => {
  const doc = { header: sampleHeader({ subscription_expires_at: future }) };
  const payload = {
    file_index: [
      queueFile("expired", { expires_at: "2026-03-24T20:31:55Z" }),
      queueFile("valid", { expires_at: future }),
    ],
  };
  const rows = listRecoverableFiles(doc, payload, { now });
  assert.equal(rows[0].recoverable, false);
  assert.equal(rows[0].code, "QRM_EXPIRED");
  assert.equal(rows[1].recoverable, true);

  const queue = createRecoveryQueue(rows, new Set([0, 1]));
  assert.deepEqual(queue.items.map((item) => item.index), [1]);
});

test("files expiring after package expiration cannot join the recovery queue", () => {
  const doc = { header: sampleHeader({ subscription_expires_at: future }) };
  const payload = {
    file_index: [
      queueFile("too-late", { expires_at: "2026-03-26T20:31:55Z" }),
    ],
  };
  const rows = listRecoverableFiles(doc, payload, { now });
  assert.equal(rows[0].recoverable, false);
  assert.equal(rows[0].code, "QRM_EXPIRY_MISMATCH");
  assert.equal(createRecoveryQueue(rows, new Set([0])).items.length, 0);
});

test("package expiration disables queue actions fail closed", () => {
  const expiredDoc = { header: sampleHeader({ subscription_expires_at: "2026-03-24T20:31:55Z" }) };
  const payload = { file_index: [queueFile("valid", { expires_at: "2026-03-24T20:31:55Z" })] };
  const rows = listRecoverableFiles(expiredDoc, payload, { now });
  assert.equal(rows[0].recoverable, false);
  assert.equal(rows[0].code, "QRM_EXPIRED");

  assert.deepEqual(
    queueActionPermissions({
      packageVerified: false,
      payloadUnlocked: true,
      payloadConsistent: true,
      selectedValidCount: 1,
      queueActive: true,
      currentFileValid: true,
      ciphertextReady: true,
      recoveryKeyReady: true,
      currentItemComplete: true,
      hasNext: true,
    }),
    {
      fileSelection: false,
      startQueue: false,
      currentEncryptedFileDownload: false,
      copyEncryptedFileURL: false,
      currentManualCiphertextUpload: false,
      currentRecoveryKeyInput: false,
      currentDecrypt: false,
      skipCurrentFile: false,
      continueToNext: false,
      finishQueue: false,
      recoverAnotherSelection: false,
    },
  );
});

test("queue action permissions require verified package and consistent unlocked payload", () => {
  for (const state of [
    { packageVerified: false, payloadUnlocked: true, payloadConsistent: true },
    { packageVerified: true, payloadUnlocked: false, payloadConsistent: true },
    { packageVerified: true, payloadUnlocked: true, payloadConsistent: false },
  ]) {
    const permissions = queueActionPermissions({
      ...state,
      selectedValidCount: 2,
      queueActive: true,
      currentFileValid: true,
      ciphertextReady: true,
      recoveryKeyReady: true,
    });
    assert.equal(permissions.startQueue, false);
    assert.equal(permissions.currentManualCiphertextUpload, false);
    assert.equal(permissions.currentDecrypt, false);
  }

  const ready = queueActionPermissions({
    packageVerified: true,
    payloadUnlocked: true,
    payloadConsistent: true,
    selectedValidCount: 2,
  });
  assert.equal(ready.fileSelection, true);
  assert.equal(ready.startQueue, true);

  const current = queueActionPermissions({
    packageVerified: true,
    payloadUnlocked: true,
    payloadConsistent: true,
    queueActive: true,
    currentFileValid: true,
    ciphertextReady: true,
    recoveryKeyReady: true,
  });
  assert.equal(current.currentManualCiphertextUpload, true);
  assert.equal(current.currentDecrypt, true);
});

test("current file without safe encrypted-file URL keeps manual upload gated by validity", () => {
  const doc = { header: sampleHeader({ subscription_expires_at: future }) };
  const payload = {
    file_index: [
      queueFile("file-1", {
        expires_at: future,
        storage_refs: [{ kind: "provider_piece_url", value: "http://unsafe.example/piece/1" }],
      }),
    ],
  };
  const rows = listRecoverableFiles(doc, payload, { now });
  assert.equal(rows[0].recoverable, true);
  assert.equal(rows[0].hasSafeCiphertextURL, false);
  assert.equal(selectCiphertextDownloadSource(payload, rows[0].file), null);

  const permissions = queueActionPermissions({
    packageVerified: true,
    payloadUnlocked: true,
    payloadConsistent: true,
    queueActive: true,
    currentFileValid: true,
  });
  assert.equal(permissions.currentEncryptedFileDownload, true);
  assert.equal(permissions.currentManualCiphertextUpload, true);
});

test("queue UI exposes only one current-file encrypted-file link surface", async () => {
  const [indexHTML, appSource] = await Promise.all([
    readFile(new URL("./index.html", import.meta.url), "utf8"),
    readFile(new URL("./app.mjs", import.meta.url), "utf8"),
  ]);
  assert.match(indexHTML, /Only the current file's encrypted-file link is shown/);
  assert.equal((indexHTML.match(/id="ciphertext-download-link"/g) ?? []).length, 1);
  assert.equal((indexHTML.match(/id="ciphertext-link-section"/g) ?? []).length, 1);
  assert.equal((indexHTML.match(/id="manual-ciphertext-input"/g) ?? []).length, 1);
  assert.match(appSource, /renderCiphertextDownloadStep\(current\.file\)/);
  assert.equal((appSource.match(/selectCiphertextDownloadSource\(/g) ?? []).length, 1);
});

test("completed current queue item advances to the next file", () => {
  const doc = { header: sampleHeader({ subscription_expires_at: future }) };
  const payload = {
    file_index: [
      queueFile("file-a", { expires_at: future }),
      queueFile("file-b", { expires_at: future }),
    ],
  };
  const rows = listRecoverableFiles(doc, payload, { now });
  let queue = createRecoveryQueue(rows, new Set([0, 1]));
  queue = markQueueCurrentItem(queue, "recovered", "Recovered");
  queue = advanceRecoveryQueue(queue);

  assert.equal(getQueueCurrentItem(queue).index, 1);
  assert.equal(getQueueCurrentItem(queue).status, "current");
  assert.equal(queue.items[0].status, "recovered");
});

test("switching current file clears ciphertext and plaintext readiness without losing queued Recovery Key by default", () => {
  assert.deepEqual(
    resetCurrentFileTransientState({
      ciphertextReady: true,
      recoveryKeyReady: true,
      plaintextReady: true,
    }),
    {
      ciphertextReady: false,
      recoveryKeyReady: true,
      plaintextReady: false,
    },
  );
  assert.deepEqual(
    resetCurrentFileTransientState({
      ciphertextReady: true,
      recoveryKeyReady: true,
      plaintextReady: true,
    }, { preserveRecoveryKey: false }),
    {
      ciphertextReady: false,
      recoveryKeyReady: false,
      plaintextReady: false,
    },
  );
});

test("Recovery Key queue reuse is memory-only and reset cleanup clears readiness", async () => {
  assert.deepEqual(
    resetCurrentFileTransientState({
      ciphertextReady: true,
      recoveryKeyReady: true,
      plaintextReady: true,
    }, { preserveRecoveryKey: false }),
    {
      ciphertextReady: false,
      recoveryKeyReady: false,
      plaintextReady: false,
    },
  );

  const appSource = await readFile(new URL("./app.mjs", import.meta.url), "utf8");
  assert.match(appSource, /clearCurrentFileState\(\{ preserveRecoveryKey: hasNext \}\)/);
  assert.match(appSource, /state\.recoveryKey = "";/);
  assert.match(appSource, /els\.recoveryKey\.value = "";/);
  assert.doesNotMatch(appSource, /\blocalStorage\b|\bsessionStorage\b|\bindexedDB\b|\bIndexedDB\b/);
});

test("browser recovery code has no combined zip or restore-all action", async () => {
  const [indexHTML, appSource, coreSource] = await Promise.all([
    readFile(new URL("./index.html", import.meta.url), "utf8"),
    readFile(new URL("./app.mjs", import.meta.url), "utf8"),
    readFile(new URL("./core.mjs", import.meta.url), "utf8"),
  ]);
  const browserCode = [indexHTML, appSource, coreSource].join("\n");
  assert.doesNotMatch(browserCode, /Restore all as ZIP|restore-all|restoreAll|JSZip|new\s+Zip/i);
});

test("browser recovery code keeps no-network and no-storage boundaries", async () => {
  const sources = await Promise.all([
    readFile(new URL("./index.html", import.meta.url), "utf8"),
    readFile(new URL("./style.css", import.meta.url), "utf8"),
    readFile(new URL("./app.mjs", import.meta.url), "utf8"),
    readFile(new URL("./core.mjs", import.meta.url), "utf8"),
  ]);
  const browserCode = sources.join("\n");
  for (const pattern of [
    /\bfetch\s*\(/,
    /\bXMLHttpRequest\b/,
    /\bsendBeacon\b/,
    /\blocalStorage\b/,
    /\bsessionStorage\b/,
    /\bindexedDB\b|\bIndexedDB\b/,
    /\bserviceWorker\b/,
    /\banalytics\b/i,
    /\bsentry\b/i,
    /\brollbar\b/i,
  ]) {
    assert.doesNotMatch(browserCode, pattern);
  }
});

async function signedFixture({ expiresAt }) {
  const keyPair = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  const publicKey = new Uint8Array(await crypto.subtle.exportKey("raw", keyPair.publicKey));
  const doc = {
    header: sampleHeader({
      subscription_expires_at: expiresAt,
      payload_encryption: {
        algorithm: "AES-256-GCM",
        kdf: "HKDF-SHA-256",
        nonce: encodeBase64(new Uint8Array(12).fill(7)),
        binding: "wallet_bound_personal_sign_v1",
        payload_protection: "wallet_bound_encrypted",
        encoding: "base64",
        signing_scope: "session_bound_v1",
        signing_scope_version: "v1",
        signing_challenge: [
          "qave-recovery-export-session:v1",
          `wallet=${owner}`,
          "issued_at=2026-03-24T20:30:00.000Z",
          "nonce=dGVzdC1ub25jZQ==",
          "purpose=enable_recovery_map_export_session",
        ].join("\n"),
      },
    }),
    payload_ciphertext: encodeBase64(new Uint8Array([1, 2, 3])),
    payload_tag: encodeBase64(new Uint8Array(16).fill(3)),
  };
  const manifest = canonicalRecoverySignedManifestJSON(doc.header, 1, recoveryFlowVersion);
  const manifestHash = await recoverySignedManifestHashHex(doc.header, 1, recoveryFlowVersion);
  const signature = new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, keyPair.privateKey, utf8(manifest)));
  doc.header.qave_signature = {
    key_id: "qave-recovery-2026-v1",
    algorithm: "Ed25519",
    recovery_flow_version: recoveryFlowVersion,
    file_count: 1,
    manifest_sha256: manifestHash,
    signature: encodeBase64(signature),
  };
  return { doc, publicKey };
}

async function encryptedSignedFixture({ keyPair, packageID, signatureHex }) {
  const publicKey = new Uint8Array(await crypto.subtle.exportKey("raw", keyPair.publicKey));
  const header = sampleHeader({
    package_id: packageID,
    subscription_expires_at: future,
    payload_encryption: {
      algorithm: "AES-256-GCM",
      kdf: "HKDF-SHA-256",
      nonce: encodeBase64(new Uint8Array(12).fill(7)),
      binding: "wallet_bound_personal_sign_v1",
      payload_protection: "wallet_bound_encrypted",
      encoding: "base64",
      signing_scope: "legacy_per_export",
    },
  });
  const payload = samplePayload(header);
  const manifest = canonicalRecoverySignedManifestJSON(header, 1, recoveryFlowVersion);
  const manifestHash = await recoverySignedManifestHashHex(header, 1, recoveryFlowVersion);
  const signature = new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, keyPair.privateKey, utf8(manifest)));
  header.qave_signature = {
    key_id: "qave-recovery-2026-v1",
    algorithm: "Ed25519",
    recovery_flow_version: recoveryFlowVersion,
    file_count: 1,
    manifest_sha256: manifestHash,
    signature: encodeBase64(signature),
  };

  const payloadKey = await deriveLegacyUnlockKeyForTest(header, signatureHex);
  const sealed = await aesGCMEncryptForTest(
    payloadKey,
    decodeBase64(header.payload_encryption.nonce),
    utf8(JSON.stringify(payload)),
    decodeHexForTest(manifestHash),
  );
  return {
    doc: {
      header,
      payload_ciphertext: encodeBase64(sealed.slice(0, sealed.length - 16)),
      payload_tag: encodeBase64(sealed.slice(sealed.length - 16)),
    },
    publicKey,
  };
}

function samplePayload(header) {
  return {
    snapshot: {
      schema_version: "qave.recovery-package.v1",
      package_id: header.package_id,
      map_id: header.map_id,
      vault_owner: header.vault_owner.trim().toLowerCase(),
      vault_state_hash: header.vault_state_hash,
      generated_at: header.generated_at,
      subscription_expires_at: header.subscription_expires_at,
      file_count: 1,
      package_protection_mode: "wallet_bound_encrypted",
      recovery_flow_version: recoveryFlowVersion,
      recovery_kdf_profiles: [],
    },
    fwss_network: "",
    fwss_api_version: "",
    file_index: [
      {
        file_id: "00000000-0000-4000-8000-000000000001",
        file_name: "alpha.txt",
        logical_path: "alpha.txt",
        name: "alpha.txt",
        size: 5,
        mime_type: null,
        cid: "",
        storage_refs: [],
        uploaded_at: "2026-03-24T20:00:00Z",
        snapshot_index: 0,
        expires_at: future,
        status: "stored",
        encryption: {
          mode: "phase1-transport-schema-only",
          key_material_included: false,
          key_derivation: "phase2-wallet-bound-hkdf-reserved",
          wallet_binding: "not_included_in_phase1",
        },
        content_encryption: null,
        recovery_material_version: null,
      },
    ],
    fetch_sources: [],
    wrapped_keys: [],
    recovery_policy: {
      requires_wallet_auth: true,
      requires_recovery_key: true,
      trusted_device_supported: false,
      recover_all_mode: "batch_only",
      local_decrypt_required: true,
      local_package_required: true,
    },
  };
}

async function deriveLegacyUnlockKeyForTest(header, signatureHex) {
  const challenge = [
    "qave-recovery:v1",
    `map_id=${header.map_id}`,
    `vault_owner=${header.vault_owner.trim().toLowerCase()}`,
    `vault_state_hash=${header.vault_state_hash}`,
    `generated_at=${header.generated_at}`,
    `nonce=${header.payload_encryption.nonce}`,
    "purpose=unlock_recovery_payload",
  ].join("\n");
  const signatureBytes = decodeHexForTest(signatureHex.replace(/^0x/i, ""));
  const challengeHash = await sha256BytesForTest(utf8(challenge));
  const signatureHash = await sha256BytesForTest(signatureBytes);
  const saltHash = await sha256BytesForTest(
    utf8([
      "qave-recovery-cli:v1",
      `map_id=${header.map_id}`,
      `vault_owner=${header.vault_owner.trim().toLowerCase()}`,
      `vault_state_hash=${header.vault_state_hash}`,
    ].join("\n")),
  );
  const ikmHash = await sha256BytesForTest(
    utf8([
      "qave-recovery-unlock:v1",
      `signature_hash=${hexForTest(signatureHash)}`,
      `challenge_hash=${hexForTest(challengeHash)}`,
      `vault_owner=${header.vault_owner.trim().toLowerCase()}`,
      `map_id=${header.map_id}`,
      `vault_state_hash=${header.vault_state_hash}`,
    ].join("\n")),
  );
  const hkdfKey = await crypto.subtle.importKey("raw", ikmHash, "HKDF", false, ["deriveBits"]);
  return new Uint8Array(await crypto.subtle.deriveBits({
    name: "HKDF",
    hash: "SHA-256",
    salt: saltHash,
    info: utf8("qave-recovery-payload-unlock-key/v1"),
  }, hkdfKey, 256));
}

async function aesGCMEncryptForTest(keyBytes, ivBytes, plaintextBytes, aadBytes) {
  const key = await crypto.subtle.importKey("raw", keyBytes, { name: "AES-GCM" }, false, ["encrypt"]);
  return new Uint8Array(await crypto.subtle.encrypt({
    name: "AES-GCM",
    iv: ivBytes,
    additionalData: aadBytes,
    tagLength: 128,
  }, key, plaintextBytes));
}

async function sha256BytesForTest(bytes) {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
}

function decodeHexForTest(value) {
  const bytes = new Uint8Array(value.length / 2);
  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = Number.parseInt(value.slice(index * 2, index * 2 + 2), 16);
  }
  return bytes;
}

function hexForTest(bytes) {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function queueFile(fileID, overrides = {}) {
  return {
    file_id: fileID,
    file_name: `${fileID}.txt`,
    name: `${fileID}.txt`,
    size: 5,
    cid: "",
    storage_refs: [],
    expires_at: future,
    ...overrides,
  };
}

function sampleHeader(overrides = {}) {
  return {
    schema: "qave.recovery-map.v1",
    map_id: "map-123",
    package_id: "package-123",
    generated_at: "2026-03-24T20:31:55Z",
    vault_owner: " 0xABCDEFabcdefABCDEFabcdefABCDEFabcdefABCD ",
    vault_state_hash: "vault-state-hash",
    subscription_expires_at: "2026-03-25T20:31:55Z",
    payload_encryption: {
      algorithm: "AES-256-GCM",
      kdf: "HKDF-SHA-256",
      nonce: "base64-nonce",
      binding: "wallet_personal_sign_v1",
    },
    ...overrides,
  };
}
