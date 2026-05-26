import {
  advanceRecoveryQueue,
  assertEd25519WebCryptoSupported,
  buildUnlockChallenge,
  createRecoveryQueue,
  decryptSelectedFile,
  evaluateQRMForUnlock,
  getQueueCurrentItem,
  listRecoverableFiles,
  markQueueCurrentItem,
  normalizeWalletAddress,
  parseQRMText,
  personalSignMessageHex,
  queueActionPermissions,
  queueStatusCounts,
  RecoveryToolError,
  safeDownloadName,
  safeErrorMessage,
  selectCiphertextDownloadSource,
  summarizeQRM,
  unlockPayloadWithSignature,
  validateTargetFileReady,
  zeroBytes,
} from "./core.mjs";

const terminalQueueStatuses = new Set(["recovered", "skipped"]);

const state = {
  doc: null,
  gate: null,
  payload: null,
  fileRows: [],
  selectedIndexes: new Set(),
  queue: null,
  selectedFile: null,
  selectedIndex: -1,
  targetFileValid: false,
  ciphertextBytes: null,
  ciphertextSource: "",
  recoveryKey: "",
  walletAddress: "",
};

const els = {
  qrmInput: byID("qrm-input"),
  resetButton: byID("reset-button"),
  summary: byID("summary"),
  packageStatus: byID("package-status"),
  unlockSection: byID("unlock-section"),
  challengeText: byID("challenge-text"),
  connectWalletButton: byID("connect-wallet-button"),
  unlockStatus: byID("unlock-status"),
  fileSection: byID("file-section"),
  fileList: byID("file-list"),
  startQueueButton: byID("start-queue-button"),
  recoverAnotherSelectionButton: byID("recover-another-selection-button"),
  fileStatus: byID("file-status"),
  queueSection: byID("queue-section"),
  queueList: byID("queue-list"),
  queueProgress: byID("queue-progress"),
  queueSummary: byID("queue-summary"),
  currentFilePanel: byID("current-file-panel"),
  currentFilePosition: byID("current-file-position"),
  currentFileTitle: byID("current-file-title"),
  currentFileMeta: byID("current-file-meta"),
  currentFileStatus: byID("current-file-status"),
  downloadStepTitle: byID("download-step-title"),
  downloadStepNote: byID("download-step-note"),
  uploadStepTitle: byID("upload-step-title"),
  uploadStepNote: byID("upload-step-note"),
  decryptStepTitle: byID("decrypt-step-title"),
  decryptStepNote: byID("decrypt-step-note"),
  ciphertextLinkSection: byID("ciphertext-link-section"),
  ciphertextDownloadLink: byID("ciphertext-download-link"),
  ciphertextURL: byID("ciphertext-url"),
  copyCiphertextURLButton: byID("copy-ciphertext-url-button"),
  noCiphertextURL: byID("no-ciphertext-url"),
  copyStatus: byID("copy-status"),
  manualCiphertextInput: byID("manual-ciphertext-input"),
  recoveryKey: byID("recovery-key"),
  decryptButton: byID("decrypt-button"),
  skipFileButton: byID("skip-file-button"),
  continueButton: byID("continue-button"),
};

els.qrmInput.addEventListener("change", onQRMSelected);
els.resetButton.addEventListener("click", resetAll);
els.connectWalletButton.addEventListener("click", connectWalletAndUnlock);
els.fileList.addEventListener("change", onFileSelectionChanged);
els.startQueueButton.addEventListener("click", startRecoveryQueue);
els.recoverAnotherSelectionButton.addEventListener("click", recoverAnotherSelection);
els.copyCiphertextURLButton.addEventListener("click", copyCiphertextURL);
els.manualCiphertextInput.addEventListener("change", onManualCiphertextSelected);
els.recoveryKey.addEventListener("input", onRecoveryKeyInput);
els.decryptButton.addEventListener("click", decryptCurrentCiphertext);
els.skipFileButton.addEventListener("click", skipCurrentFile);
els.continueButton.addEventListener("click", continueQueue);

void renderInitial();

function byID(id) {
  return document.getElementById(id);
}

async function renderInitial() {
  try {
    await assertEd25519WebCryptoSupported();
    els.qrmInput.disabled = false;
    setStatus(els.packageStatus, "Select a .qrm package to begin.", "");
  } catch (error) {
    els.qrmInput.disabled = true;
    setStatus(els.packageStatus, safeErrorMessage(error), "error");
  }
  hide(els.unlockSection);
  hide(els.fileSection);
  hide(els.queueSection);
  hide(els.currentFilePanel);
  renderSummary(null);
}

async function onQRMSelected() {
  resetSensitiveState();
  const file = els.qrmInput.files?.[0];
  if (!file) {
    await renderInitial();
    return;
  }
  try {
    const text = await file.text();
    state.doc = parseQRMText(text);
    renderSummary(summarizeQRM(state.doc));
    const evaluated = await evaluateQRMForUnlock(state.doc);
    if (!evaluated.ok) {
      setStatus(els.packageStatus, evaluated.message, "error");
      hide(els.unlockSection);
      return;
    }
    state.gate = evaluated.gate;
    setStatus(els.packageStatus, "Package signature and access period verified.", "ok");
    els.challengeText.textContent = buildUnlockChallenge(state.doc);
    show(els.unlockSection);
  } catch (error) {
    setStatus(els.packageStatus, safeErrorMessage(error), "error");
    hide(els.unlockSection);
  }
}

async function connectWalletAndUnlock() {
  if (!state.doc || !state.gate) return;
  setStatus(els.unlockStatus, "Waiting for wallet signature.", "");
  try {
    const ethereum = globalThis.ethereum;
    if (!ethereum?.request) {
      throw new RecoveryToolError("WALLET_PROVIDER_UNAVAILABLE", "MetaMask provider is unavailable");
    }
    const accounts = await ethereum.request({ method: "eth_requestAccounts" });
    const account = normalizeWalletAddress(accounts?.[0]);
    if (account !== normalizeWalletAddress(state.doc.header.vault_owner)) {
      throw new RecoveryToolError("WALLET_ADDRESS_MISMATCH", "connected wallet does not match vault_owner");
    }
    const challenge = buildUnlockChallenge(state.doc);
    const signature = await ethereum.request({
      method: "personal_sign",
      params: [personalSignMessageHex(challenge), account],
    });
    await completeUnlock(signature, account);
  } catch (error) {
    setStatus(els.unlockStatus, safeErrorMessage(error), "error");
  }
}

async function completeUnlock(signature, walletAddress) {
  const result = await unlockPayloadWithSignature(state.doc, signature, walletAddress, { gate: state.gate });
  state.payload = result.payload;
  state.walletAddress = result.walletAddress;
  state.fileRows = listRecoverableFiles(state.doc, state.payload);
  setStatus(els.unlockStatus, "Package payload unlocked and matched to the signed header.", "ok");
  renderFileSelection();
}

function renderFileSelection() {
  clearQueueState({ preserveRecoveryKey: false });
  state.selectedIndexes.clear();
  els.fileList.textContent = "";
  hide(els.queueSection);
  hide(els.currentFilePanel);
  hide(els.recoverAnotherSelectionButton);

  if (state.fileRows.length === 0) {
    setStatus(els.fileStatus, "No files are listed in this package.", "error");
  } else {
    for (const row of state.fileRows) {
      els.fileList.appendChild(fileRowElement(row));
    }
    const readyCount = state.fileRows.filter((row) => row.recoverable).length;
    setStatus(
      els.fileStatus,
      readyCount > 0
        ? "Select one or more files, then start the recovery queue."
        : "No files in this package are currently recoverable.",
      readyCount > 0 ? "" : "error",
    );
  }

  show(els.fileSection);
  renderSelectionGate();
}

function fileRowElement(row) {
  const label = document.createElement("label");
  label.className = `file-row${row.recoverable ? "" : " is-disabled"}`;

  const checkbox = document.createElement("input");
  checkbox.type = "checkbox";
  checkbox.value = String(row.index);
  checkbox.dataset.index = String(row.index);
  checkbox.disabled = !row.recoverable;

  const main = document.createElement("span");
  main.className = "file-row-main";

  const name = document.createElement("span");
  name.className = "file-row-name";
  name.textContent = fileDisplayName(row.file);

  const meta = document.createElement("span");
  meta.className = "file-row-meta";
  meta.textContent = `${formatBytes(row.file?.size)} | valid until ${row.file?.expires_at ?? "-"}`;

  const status = document.createElement("span");
  status.className = `file-row-status${row.recoverable ? "" : " is-error"}`;
  status.textContent = row.recoverable
    ? row.hasSafeCiphertextURL
      ? "Ready"
      : "Ready; encrypted-file link unavailable"
    : row.message;

  main.append(name, meta);
  label.append(checkbox, main, status);
  return label;
}

function onFileSelectionChanged(event) {
  const input = event.target;
  if (!(input instanceof HTMLInputElement) || input.type !== "checkbox") return;
  const index = Number(input.dataset.index);
  if (!Number.isInteger(index)) return;
  if (input.checked) {
    state.selectedIndexes.add(index);
  } else {
    state.selectedIndexes.delete(index);
  }
  renderSelectionGate();
}

function renderSelectionGate() {
  const selectedValidCount = countSelectedRecoverableFiles();
  const permissions = queueActionPermissions({
    packageVerified: Boolean(state.gate),
    payloadUnlocked: Boolean(state.payload),
    payloadConsistent: Boolean(state.payload),
    selectedValidCount,
    queueActive: Boolean(state.queue),
  });
  els.startQueueButton.disabled = !permissions.startQueue;
  if (state.fileRows.length > 0 && !state.queue) {
    setStatus(
      els.fileStatus,
      selectedValidCount > 0
        ? `${selectedValidCount} file${selectedValidCount === 1 ? "" : "s"} selected. Each recovered file downloads separately.`
        : "Select one or more recoverable files to start.",
      "",
    );
  }
}

function countSelectedRecoverableFiles() {
  return state.fileRows.filter((row) => row.recoverable && state.selectedIndexes.has(row.index)).length;
}

function startRecoveryQueue() {
  const queue = createRecoveryQueue(state.fileRows, state.selectedIndexes);
  if (!queue.items.length) {
    setStatus(els.fileStatus, "Select at least one recoverable file to continue.", "error");
    return;
  }
  state.queue = queue;
  clearCurrentFileState({ preserveRecoveryKey: false });
  setStatus(els.fileStatus, "Recovery queue started.", "ok");
  show(els.queueSection);
  hide(els.recoverAnotherSelectionButton);
  renderQueue();
}

function recoverAnotherSelection() {
  renderFileSelection();
}

function renderQueue() {
  if (!state.queue) {
    hide(els.queueSection);
    return;
  }

  show(els.queueSection);
  renderQueueList();
  const current = getQueueCurrentItem(state.queue);
  const counts = queueStatusCounts(state.queue);
  els.queueProgress.textContent = `Completed ${counts.recovered} of ${counts.total}. Failed ${counts.failed}. Skipped ${counts.skipped}.`;

  if (!current) {
    finishQueueView();
    return;
  }

  state.selectedFile = current.file;
  state.selectedIndex = current.index;
  try {
    validateTargetFileReady(state.doc, current.file);
    state.targetFileValid = true;
  } catch (error) {
    state.targetFileValid = false;
    state.queue = markQueueCurrentItem(state.queue, "failed", safeErrorMessage(error));
  }

  renderCurrentFile();
}

function renderQueueList() {
  els.queueList.textContent = "";
  if (!state.queue) return;
  for (const item of state.queue.items) {
    const row = document.createElement("li");
    row.className = `queue-item queue-item-${item.status}`;

    const name = document.createElement("span");
    name.className = "queue-item-name";
    name.textContent = fileDisplayName(item.file);

    const status = document.createElement("span");
    status.className = "queue-item-status";
    status.textContent = queueStatusLabel(item.status);

    row.append(name, status);
    els.queueList.appendChild(row);
  }
}

function renderCurrentFile() {
  const current = getQueueCurrentItem(state.queue);
  if (!current) {
    finishQueueView();
    return;
  }

  show(els.currentFilePanel);
  const currentName = fileDisplayName(current.file);
  const currentNumber = Number(state.queue?.currentPosition ?? 0) + 1;
  const totalCount = Array.isArray(state.queue?.items) ? state.queue.items.length : 0;
  els.currentFilePosition.textContent = `Recovering file ${currentNumber} of ${totalCount}`;
  els.currentFileTitle.textContent = `Current file: ${currentName}`;
  els.currentFileMeta.textContent = `${formatBytes(current.file?.size)} | valid until ${current.file?.expires_at ?? "-"}`;
  els.downloadStepTitle.textContent = `Step 1: Download encrypted file for ${currentName}`;
  els.downloadStepNote.textContent = "Use the encrypted-file link for the current file, then upload that encrypted file here.";
  els.uploadStepTitle.textContent = `Step 2: Upload the encrypted file for ${currentName}`;
  els.uploadStepNote.textContent = `Upload only the encrypted file for ${currentName}. It is not reused for other files.`;
  els.decryptStepTitle.textContent = `Step 3: Decrypt and download ${currentName}`;
  els.decryptStepNote.textContent = "Recovery Key is kept in memory for this page session only.";
  renderCiphertextDownloadStep(current.file);
  renderCurrentStatus(current);
  renderCurrentControls();
}

function renderCurrentStatus(current) {
  switch (current.status) {
    case "uploaded":
      setStatus(els.currentFileStatus, "Encrypted file uploaded. Enter your Recovery Key and decrypt this file.", "ok");
      break;
    case "recovered":
      setStatus(els.currentFileStatus, `${fileDisplayName(current.file)} recovered successfully.`, "ok");
      break;
    case "failed":
      setStatus(els.currentFileStatus, current.message || "Decrypt failed. You can re-enter the Recovery Key and try again, or skip this file.", "error");
      break;
    case "skipped":
      setStatus(els.currentFileStatus, "This file was skipped.", "");
      break;
    default:
      setStatus(els.currentFileStatus, "Use the encrypted-file link for the current file, then upload that encrypted file here.", "");
      break;
  }
}

function renderCurrentControls() {
  const current = getQueueCurrentItem(state.queue);
  const currentComplete = current ? terminalQueueStatuses.has(current.status) : false;
  const hasNext = queueHasNextWaitingItem();
  const permissions = queueActionPermissions({
    packageVerified: Boolean(state.gate),
    payloadUnlocked: Boolean(state.payload),
    payloadConsistent: Boolean(state.payload),
    queueActive: Boolean(state.queue),
    currentFileValid: state.targetFileValid,
    ciphertextReady: state.ciphertextBytes instanceof Uint8Array,
    recoveryKeyReady: state.recoveryKey.trim().length > 0,
    currentItemComplete: currentComplete,
    hasNext,
  });

  els.manualCiphertextInput.disabled = !permissions.currentManualCiphertextUpload || currentComplete;
  els.recoveryKey.disabled = !permissions.currentRecoveryKeyInput || currentComplete;
  els.decryptButton.disabled = !permissions.currentDecrypt || currentComplete;
  els.skipFileButton.disabled = !permissions.skipCurrentFile || currentComplete;

  const canContinue = permissions.continueToNext || permissions.finishQueue;
  els.continueButton.hidden = !canContinue;
  els.continueButton.textContent = permissions.continueToNext ? "Continue to next file" : "Finish queue";
}

function renderCiphertextDownloadStep(file) {
  const source = selectCiphertextDownloadSource(state.payload, file);
  if (!source) {
    clearCiphertextURL();
    show(els.noCiphertextURL);
    els.noCiphertextURL.textContent = "No direct encrypted-file URL is available for the current file. Use the CLI or another trusted method to obtain the ciphertext, then upload it here.";
    return;
  }

  hide(els.noCiphertextURL);
  els.ciphertextDownloadLink.href = source.url;
  els.ciphertextDownloadLink.textContent = `Download encrypted file for ${fileDisplayName(file)}`;
  els.ciphertextURL.value = source.url;
  els.copyCiphertextURLButton.disabled = false;
  show(els.ciphertextLinkSection);
}

function clearCiphertextURL() {
  els.ciphertextDownloadLink.removeAttribute("href");
  els.ciphertextURL.value = "";
  els.copyCiphertextURLButton.disabled = true;
  setStatus(els.copyStatus, "", "");
  hide(els.ciphertextLinkSection);
  hide(els.noCiphertextURL);
}

async function copyCiphertextURL() {
  const value = els.ciphertextURL.value.trim();
  if (!value) return;
  try {
    await navigator.clipboard.writeText(value);
    setStatus(els.copyStatus, "Encrypted file URL copied.", "ok");
  } catch {
    setStatus(els.copyStatus, "Copy failed. Select the URL text and copy it manually.", "error");
  }
}

async function onManualCiphertextSelected() {
  const current = getQueueCurrentItem(state.queue);
  if (!current || !state.targetFileValid) return;
  const file = els.manualCiphertextInput.files?.[0];
  if (!file) return;
  try {
    validateTargetFileReady(state.doc, current.file);
    const bytes = new Uint8Array(await file.arrayBuffer());
    setCiphertext(bytes);
  } catch (error) {
    clearCurrentFileState({ preserveRecoveryKey: true });
    setStatus(els.currentFileStatus, safeErrorMessage(error), "error");
  }
}

function setCiphertext(bytes) {
  clearCurrentFileState({ preserveRecoveryKey: true });
  state.ciphertextBytes = bytes;
  state.ciphertextSource = "Manual ciphertext loaded.";
  state.queue = markQueueCurrentItem(state.queue, "uploaded", "Encrypted file uploaded");
  renderQueue();
}

function onRecoveryKeyInput() {
  state.recoveryKey = els.recoveryKey.value;
  renderCurrentControls();
}

async function decryptCurrentCiphertext() {
  const current = getQueueCurrentItem(state.queue);
  if (!current || !(state.ciphertextBytes instanceof Uint8Array)) return;
  state.recoveryKey = els.recoveryKey.value;
  setStatus(els.currentFileStatus, "Decrypting locally.", "");
  let plaintext = null;
  try {
    validateTargetFileReady(state.doc, current.file);
    plaintext = await decryptSelectedFile(state.payload, current.file, state.ciphertextBytes, state.recoveryKey);
    triggerDownload(plaintext, safeDownloadName(current.file, current.index));
    state.queue = markQueueCurrentItem(state.queue, "recovered", "Recovered");
    clearCurrentFileState({ preserveRecoveryKey: true });
    renderQueue();
  } catch (error) {
    state.queue = markQueueCurrentItem(state.queue, "failed", safeErrorMessage(error));
    renderQueue();
  } finally {
    if (plaintext instanceof Uint8Array) {
      zeroBytes(plaintext);
    }
  }
}

function skipCurrentFile() {
  const current = getQueueCurrentItem(state.queue);
  if (!current || terminalQueueStatuses.has(current.status)) return;
  state.queue = markQueueCurrentItem(state.queue, "skipped", "Skipped");
  clearCurrentFileState({ preserveRecoveryKey: true });
  renderQueue();
}

function continueQueue() {
  if (!state.queue) return;
  const current = getQueueCurrentItem(state.queue);
  if (!current || !terminalQueueStatuses.has(current.status)) return;
  const hasNext = queueHasNextWaitingItem();
  state.queue = advanceRecoveryQueue(state.queue);
  clearCurrentFileState({ preserveRecoveryKey: hasNext });
  renderQueue();
}

function finishQueueView() {
  clearCurrentFileState({ preserveRecoveryKey: false });
  state.selectedFile = null;
  state.selectedIndex = -1;
  state.targetFileValid = false;
  hide(els.currentFilePanel);
  show(els.recoverAnotherSelectionButton);
  const counts = queueStatusCounts(state.queue);
  setStatus(
    els.queueSummary,
    `Queue complete. Completed ${counts.recovered} of ${counts.total}. Failed ${counts.failed}. Skipped ${counts.skipped}.`,
    counts.failed > 0 ? "error" : "ok",
  );
  renderQueueList();
  renderSelectionGate();
}

function queueHasNextWaitingItem() {
  if (!state.queue) return false;
  const currentPosition = Number(state.queue.currentPosition ?? -1);
  return state.queue.items.some((item, index) => index > currentPosition && item.status === "waiting");
}

function triggerDownload(bytes, name) {
  const blob = new Blob([bytes], { type: "application/octet-stream" });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = name;
  anchor.rel = "noopener";
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function renderSummary(summary) {
  els.summary.textContent = "";
  const rows = summary
    ? [
        ["key_id", summary.key_id],
        ["vault_owner", summary.vault_owner],
        ["generated_at", summary.generated_at],
        ["subscription_expires_at", summary.subscription_expires_at],
        ["file_count", String(summary.file_count)],
        ["package_id", summary.package_id],
      ]
    : [
        ["key_id", ""],
        ["vault_owner", ""],
        ["generated_at", ""],
        ["subscription_expires_at", ""],
        ["file_count", ""],
        ["package_id", ""],
      ];
  for (const [label, value] of rows) {
    const dt = document.createElement("dt");
    dt.textContent = label;
    const dd = document.createElement("dd");
    dd.textContent = value || "-";
    els.summary.append(dt, dd);
  }
}

function fileDisplayName(file) {
  return `${file?.name || file?.file_name || file?.file_id || "Unnamed file"}`.trim() || "Unnamed file";
}

function formatBytes(value) {
  const size = Number(value ?? 0);
  if (!Number.isFinite(size) || size <= 0) return "0 bytes";
  if (size < 1024) return `${size} bytes`;
  if (size < 1024 * 1024) return `${(size / 1024).toFixed(1)} KB`;
  if (size < 1024 * 1024 * 1024) return `${(size / (1024 * 1024)).toFixed(1)} MB`;
  return `${(size / (1024 * 1024 * 1024)).toFixed(1)} GB`;
}

function queueStatusLabel(status) {
  switch (status) {
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
      return "Waiting";
  }
}

function setStatus(element, message, tone) {
  element.textContent = message;
  element.dataset.tone = tone || "";
}

function show(element) {
  element.hidden = false;
}

function hide(element) {
  element.hidden = true;
}

function resetSensitiveState() {
  clearQueueState({ preserveRecoveryKey: false });
  state.doc = null;
  state.gate = null;
  state.payload = null;
  state.fileRows = [];
  state.selectedIndexes.clear();
  state.walletAddress = "";
  els.fileList.textContent = "";
  setStatus(els.unlockStatus, "", "");
  setStatus(els.fileStatus, "", "");
  setStatus(els.queueSummary, "", "");
  setStatus(els.currentFileStatus, "", "");
  hide(els.unlockSection);
  hide(els.fileSection);
  hide(els.queueSection);
  hide(els.currentFilePanel);
  hide(els.recoverAnotherSelectionButton);
}

function clearQueueState(options = {}) {
  clearCurrentFileState(options);
  state.queue = null;
  state.selectedFile = null;
  state.selectedIndex = -1;
  state.targetFileValid = false;
  clearCiphertextURL();
  els.queueList.textContent = "";
  els.queueProgress.textContent = "";
}

function clearCurrentFileState(options = {}) {
  if (state.ciphertextBytes instanceof Uint8Array) {
    zeroBytes(state.ciphertextBytes);
  }
  state.ciphertextBytes = null;
  state.ciphertextSource = "";
  els.manualCiphertextInput.value = "";
  if (options.preserveRecoveryKey === false) {
    state.recoveryKey = "";
    els.recoveryKey.value = "";
  }
}

function resetAll() {
  resetSensitiveState();
  els.qrmInput.value = "";
  void renderInitial();
}
