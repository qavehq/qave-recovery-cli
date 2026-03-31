package main

import (
	"archive/zip"
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type restoreAllOptions struct {
	QRMPath       string
	Signer        string
	OutputZipName string
	PieceBaseURL  string
	NoBrowser     bool
}

func runRestoreAll(args []string, stdout io.Writer, stdin io.Reader, now time.Time) error {
	options, err := parseRestoreAllArgs(args)
	if err != nil {
		return err
	}

	doc, err := loadRecoveryMap(options.QRMPath)
	if err != nil {
		return err
	}
	if err := validateRecoveryMap(doc, now); err != nil {
		return err
	}

	if payloadProtectionOf(doc) == payloadProtectionLegacyPlaintext {
		_, _ = fmt.Fprintf(stdout, "payload_protection=%s\n", payloadProtectionLegacyPlaintext)
		_, _ = fmt.Fprintf(stdout, "challenge_verified=false\n")
		_, _ = fmt.Fprintf(stdout, "payload_unlocked=true\n")
		_, _ = fmt.Fprintf(stdout, "package_structure=%s\n", packageStructureLegacyRecoveryMap)
		return newCLIError("RECOVERY_PACKAGE_REQUIRED", "restore-all requires a Recovery Package v1 structure")
	}

	stdinReader := bufio.NewReader(stdin)
	var result unlockResult

	switch options.Signer {
	case "metamask":
		result, err = unlockRecoveryMap(doc, options.Signer, stdout, stdinReader, now)
		if err != nil {
			return err
		}
	case "manual":
		signatureLine, err := stdinReader.ReadString('\n')
		if err != nil && err != io.EOF {
			return err
		}
		signature := strings.TrimSpace(signatureLine)
		if signature == "" {
			return newCLIError("SIGNATURE_REJECTED", "manual signer did not provide a signature")
		}
		result, err = unlockRecoveryMapWithProvidedSignature(doc, stdout, stdinReader, now, signature)
		if err != nil {
			return err
		}
	default:
		return newCLIError("UNSUPPORTED_SIGNER", "supported signers are metamask and manual")
	}

	if len(result.payload.FileIndex) == 0 {
		return newCLIError("NO_FILES_TO_RESTORE", "the recovery package contains no files")
	}

	_, _ = fmt.Fprintf(stdout, "wallet_address=%s\n", result.recoveredAddress)
	_, _ = fmt.Fprintf(stdout, "challenge_verified=true\n")
	_, _ = fmt.Fprintf(stdout, "unlock_key_fingerprint=%s\n", fingerprintUnlockKey(result.key))
	_, _ = fmt.Fprintf(stdout, "payload_unlocked=true\n")
	_, _ = fmt.Fprintf(stdout, "files_to_restore=%d\n", len(result.payload.FileIndex))

	_, _ = fmt.Fprint(stdout, "restore_all_requires_recovery_key=true\n")
	_, _ = fmt.Fprintf(stdout, "vault_state_hash=%s\n", doc.Header.VaultStateHash)
	_, _ = fmt.Fprintf(stdout, "restoring_files=%d\n", len(result.payload.FileIndex))

	restoreWorkspace, err := os.MkdirTemp("", "qave-restore-*")
	if err != nil {
		_, _ = fmt.Fprintf(stdout, "restore_all_failed=true\n")
		return newCLIError("RESTORE_WORKDIR_FAILED", "failed to create restore workspace: "+err.Error())
	}
	defer os.RemoveAll(restoreWorkspace)

	entries, err := restoreAllWithRecoveryKeyRetry(result.payload, options.PieceBaseURL, restoreWorkspace, stdout, stdinReader)
	if err != nil {
		_, _ = fmt.Fprintf(stdout, "restore_all_failed=true\n")
		return err
	}

	outputZip := options.OutputZipName
	if outputZip == "" {
		safeOwner := sanitizeZipEntryName(normalizeAddress(doc.Header.VaultOwner))
		outputZip = fmt.Sprintf("qave-restore-%s-%s.zip", now.UTC().Format("20060102T150405"), safeOwner)
	}

	zipBytesWritten, err := writeRestoreZip(outputZip, entries, doc, now)
	if err != nil {
		_, _ = fmt.Fprintf(stdout, "restore_all_failed=true\n")
		return err
	}

	_, _ = fmt.Fprintf(stdout, "restore_all_complete=true\n")
	_, _ = fmt.Fprintf(stdout, "files_restored=%d\n", len(entries))
	_, _ = fmt.Fprintf(stdout, "zip_path=%s\n", outputZip)
	_, _ = fmt.Fprintf(stdout, "zip_bytes=%d\n", zipBytesWritten)

	if !options.NoBrowser {
		downloadURL, bridge, err := startDownloadBridge(outputZip)
		if err != nil {
			_, _ = fmt.Fprintf(stdout, "browser_download_skipped=true\n")
			_, _ = fmt.Fprintf(stdout, "download_zip_manually=%s\n", outputZip)
		} else {
			defer bridge.Close()
			_, _ = fmt.Fprintf(stdout, "download_url=%s\n", downloadURL)
			if openErr := openBrowserURL(downloadURL); openErr != nil {
				_, _ = fmt.Fprintf(stdout, "browser_opened=false\n")
				_, _ = fmt.Fprintf(stdout, "Open this URL in your browser: %s\n", downloadURL)
			} else {
				_, _ = fmt.Fprintf(stdout, "browser_opened=true\n")
				if bridge.WaitForSingleDownload(15 * time.Second) {
					_, _ = fmt.Fprintf(stdout, "browser_download_completed=true\n")
				} else {
					_, _ = fmt.Fprintf(stdout, "browser_download_pending=true\n")
					_, _ = fmt.Fprintf(stdout, "download_zip_manually=%s\n", outputZip)
				}
			}
		}
	} else {
		_, _ = fmt.Fprintf(stdout, "browser_download_skipped=true\n")
		_, _ = fmt.Fprintf(stdout, "zip_path=%s\n", outputZip)
	}

	return nil
}

func restoreAllWithRecoveryKeyRetry(payload recoveryMapPayload, pieceBaseURL string, workspaceDir string, stdout io.Writer, stdin *bufio.Reader) ([]restoredFile, error) {
	for {
		recoveryKey, err := promptRecoveryKeyForRestoreAll(stdout, stdin)
		if err != nil {
			return nil, err
		}

		entries, err := restoreAllFiles(payload, recoveryKey, pieceBaseURL, workspaceDir, stdout)
		if err == nil {
			return entries, nil
		}
		if !isRetryableRestoreRecoveryKeyError(err) {
			return nil, err
		}

		_, _ = fmt.Fprintln(stdout, "Recovery Key incorrect. Please try again.")
	}
}

func promptRecoveryKeyForRestoreAll(stdout io.Writer, stdin *bufio.Reader) (string, error) {
	for {
		_, _ = fmt.Fprint(stdout, "Paste recovery key (hyphens/spaces optional): ")
		recoveryKeyLine, err := stdin.ReadString('\n')
		if err != nil && err != io.EOF {
			return "", err
		}
		recoveryKey, parseErr := parseRecoveryKeyMaterialCLI(recoveryKeyLine)
		if parseErr == nil {
			return recoveryKey, nil
		}
		if strings.Contains(parseErr.Error(), "RECOVERY_KEY_MISSING") {
			return "", newCLIError("RECOVERY_KEY_MISSING", "recovery key is required")
		}
		if isRetryableRecoveryKeyInputError(parseErr) {
			_, _ = fmt.Fprintln(stdout, "Recovery Key incorrect. Please try again.")
			continue
		}
		return "", parseErr
	}
}

func isRetryableRestoreRecoveryKeyError(err error) bool {
	var cliErr *cliError
	if !errors.As(err, &cliErr) {
		return false
	}
	switch cliErr.Code {
	case "RECOVERY_KEY_INVALID", "FILE_KEY_UNWRAP_FAILED":
		return true
	default:
		return false
	}
}

func isRetryableRecoveryKeyInputError(err error) bool {
	var cliErr *cliError
	if !errors.As(err, &cliErr) {
		return false
	}
	switch cliErr.Code {
	case "RECOVERY_KEY_INVALID", "RECOVERY_KEY_INVALID_FORMAT", "RECOVERY_KEY_INVALID_LENGTH", "FILE_KEY_UNWRAP_FAILED":
		return true
	default:
		return false
	}
}

func parseRestoreAllArgs(args []string) (restoreAllOptions, error) {
	if len(args) == 0 {
		return restoreAllOptions{}, newCLIError("USAGE", "restore-all requires: qave-recovery-cli restore-all <map.qrm> --signer <metamask|manual> [--output <name.zip>] [--piece-base-url <url>] [--no-browser]")
	}

	pathArg := args[0]
	restArgs := args[1:]
	if pathArg == "" || strings.HasPrefix(pathArg, "-") {
		return restoreAllOptions{}, newCLIError("USAGE", "restore-all requires: qave-recovery-cli restore-all <map.qrm> --signer <metamask|manual>")
	}

	var opts restoreAllOptions
	opts.QRMPath = pathArg
	opts.NoBrowser = false

	i := 0
	for i < len(restArgs) {
		if !strings.HasPrefix(restArgs[i], "--") {
			i++
			continue
		}
		key := restArgs[i]
		value := ""
		if i+1 < len(restArgs) && !strings.HasPrefix(restArgs[i+1], "--") {
			value = restArgs[i+1]
			i += 2
		} else {
			i++
		}

		switch key {
		case "--signer":
			opts.Signer = strings.ToLower(strings.TrimSpace(value))
		case "--output":
			opts.OutputZipName = strings.TrimSpace(value)
		case "--piece-base-url":
			opts.PieceBaseURL = strings.TrimSpace(value)
		case "--no-browser":
			opts.NoBrowser = true
		default:
			return restoreAllOptions{}, newCLIError("USAGE", "unsupported flag: "+key)
		}
	}

	if opts.Signer != "metamask" && opts.Signer != "manual" {
		return restoreAllOptions{}, newCLIError("UNSUPPORTED_SIGNER", "supported signers are metamask and manual")
	}

	if opts.QRMPath == "" {
		return restoreAllOptions{}, newCLIError("USAGE", "restore-all requires a qrm path")
	}

	return opts, nil
}

type restoredFile struct {
	name string
	path string
	data []byte
	size int64
}

func restoreAllFiles(payload recoveryMapPayload, recoveryKey string, pieceBaseURL string, workspaceDir string, stdout io.Writer) ([]restoredFile, error) {
	entries := make([]restoredFile, 0, len(payload.FileIndex))

	for i, file := range payload.FileIndex {
		fileNum := i + 1
		totalFiles := len(payload.FileIndex)

		if file.ContentEncryption == nil {
			return nil, newCLIError("CONTENT_ENCRYPTION_METADATA_MISSING", fmt.Sprintf("file %d (%s) is missing content_encryption metadata", fileNum, file.Name))
		}

		source, err := resolveFetchSource(file, pieceBaseURL)
		if err != nil {
			return nil, newCLIError("FETCH_SOURCE_ERROR", fmt.Sprintf("file %d (%s): %s", fileNum, file.Name, err.Error()))
		}

		_, _ = fmt.Fprintf(stdout, "restoring_file=%d/%d name=%s source=%s\n", fileNum, totalFiles, file.Name, source.description)

		ciphertextPath := filepath.Join(workspaceDir, "ciphertext", fmt.Sprintf("%06d.enc", fileNum))
		_, err = fetchSourceToFile(context.Background(), source, ciphertextPath)
		if err != nil {
			return nil, newCLIError("FETCH_FAILED", fmt.Sprintf("file %d (%s) fetch failed: %s", fileNum, file.Name, err.Error()))
		}

		wrappedKey, err := selectWrappedKeyByFileID(payload, strings.TrimSpace(file.FileID))
		if err != nil {
			return nil, newCLIError("WRAPPED_KEY_ERROR", fmt.Sprintf("file %d (%s): %s", fileNum, file.Name, err.Error()))
		}

		profile, err := selectRecoveryProfile(payload, file, wrappedKey)
		if err != nil {
			return nil, newCLIError("RECOVERY_PROFILE_ERROR", fmt.Sprintf("file %d (%s): %s", fileNum, file.Name, err.Error()))
		}

		wrapKeyBytes, err := deriveRecoveryWrapKeyBytes(recoveryKey, profile)
		if err != nil {
			return nil, newCLIError("RECOVERY_KEY_INVALID", fmt.Sprintf("file %d (%s): %s", fileNum, file.Name, err.Error()))
		}

		fileKeyBytes, err := unwrapRecoveryFileKey(wrapKeyBytes, wrappedKey)
		zeroBytes(wrapKeyBytes)
		if err != nil {
			return nil, newCLIError("FILE_KEY_UNWRAP_FAILED", fmt.Sprintf("file %d (%s): %s", fileNum, file.Name, err.Error()))
		}

		plaintext, err := decryptLocalCiphertext(ciphertextPath, file, fileKeyBytes)
		zeroBytes(fileKeyBytes)
		if err != nil {
			return nil, newCLIError("DECRYPT_FAILED", fmt.Sprintf("file %d (%s): %s", fileNum, file.Name, err.Error()))
		}

		relativePath := sanitizeZipRelativePath(file.Name, i)
		plaintextPath := filepath.Join(workspaceDir, "restored", filepath.FromSlash(relativePath))
		if err := os.MkdirAll(filepath.Dir(plaintextPath), 0o755); err != nil {
			zeroBytes(plaintext)
			return nil, newCLIError("RESTORE_WRITE_FAILED", fmt.Sprintf("file %d (%s): failed to create restore directory", fileNum, file.Name))
		}
		if err := os.WriteFile(plaintextPath, plaintext, 0o600); err != nil {
			zeroBytes(plaintext)
			return nil, newCLIError("RESTORE_WRITE_FAILED", fmt.Sprintf("file %d (%s): failed to write restored plaintext", fileNum, file.Name))
		}
		plaintextSize := int64(len(plaintext))
		zeroBytes(plaintext)
		entries = append(entries, restoredFile{
			name: relativePath,
			path: plaintextPath,
			size: plaintextSize,
		})
	}

	return entries, nil
}

func sanitizeZipRelativePath(fileName string, index int) string {
	trimmed := strings.TrimSpace(fileName)
	if trimmed == "" {
		return fmt.Sprintf("file-%d", index+1)
	}
	if strings.HasPrefix(trimmed, "..") || strings.HasPrefix(trimmed, "/") {
		return fmt.Sprintf("file-%d", index+1)
	}

	parts := strings.Split(trimmed, "/")
	sanitizedParts := make([]string, 0, len(parts))
	for _, part := range parts {
		if part == ".." {
			if len(sanitizedParts) == 0 {
				return fmt.Sprintf("file-%d", index+1)
			}
			sanitizedParts = sanitizedParts[:len(sanitizedParts)-1]
			continue
		}
		sanitizedParts = append(sanitizedParts, sanitizePathSegment(part))
	}

	relative := strings.Join(sanitizedParts, "/")
	if relative == "" {
		return fmt.Sprintf("file-%d", index+1)
	}
	if strings.HasPrefix(relative, "/") {
		return fmt.Sprintf("file-%d", index+1)
	}
	return relative
}

func sanitizeZipEntryName(name string) string {
	trimmed := strings.TrimSpace(name)
	if trimmed == "" {
		return "unknown"
	}
	replacer := strings.NewReplacer("/", "_", "\\", "_", "..", "_", ":", "_", " ", "_")
	return replacer.Replace(trimmed)
}

func writeRestoreZip(outputPath string, entries []restoredFile, doc recoveryMapDocument, now time.Time) (int64, error) {
	if strings.TrimSpace(outputPath) == "" {
		return 0, newCLIError("ZIP_WRITE_FAILED", "failed to write zip: output path is required")
	}
	if err := os.MkdirAll(filepath.Dir(outputPath), 0o755); err != nil {
		return 0, newCLIError("ZIP_WRITE_FAILED", "failed to create zip output directory")
	}

	tempFile, err := os.CreateTemp(filepath.Dir(outputPath), filepath.Base(outputPath)+".partial-*")
	if err != nil {
		return 0, newCLIError("ZIP_WRITE_FAILED", "failed to create temporary zip")
	}
	tempPath := tempFile.Name()
	cleanup := func() {
		_ = tempFile.Close()
		_ = os.Remove(tempPath)
	}

	zw := zip.NewWriter(tempFile)

	manifest := map[string]any{
		"schema":            doc.Header.Schema,
		"map_id":            doc.Header.MapID,
		"vault_owner":       normalizeAddress(doc.Header.VaultOwner),
		"vault_state_hash":  doc.Header.VaultStateHash,
		"generated_at":      doc.Header.GeneratedAt,
		"package_generated": doc.Header.GeneratedAt,
		"restore_at":        now.UTC().Format(time.RFC3339Nano),
		"files_restored":    len(entries),
		"recovery_flow":     "recover-all.v1",
	}
	if doc.Payload != nil && doc.Payload.Snapshot != nil {
		manifest["package_id"] = doc.Payload.Snapshot.PackageID
	}
	manifestJSON, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		cleanup()
		return 0, err
	}
	manifestHeader := &zip.FileHeader{
		Name:     "manifest.json",
		Method:   zip.Deflate,
		Modified: now,
	}
	w, err := zw.CreateHeader(manifestHeader)
	if err != nil {
		cleanup()
		return 0, err
	}
	if _, err := w.Write(manifestJSON); err != nil {
		cleanup()
		return 0, err
	}

	for _, entry := range entries {
		header := &zip.FileHeader{
			Name:     entry.name,
			Method:   zip.Deflate,
			Modified: now,
		}
		w, err := zw.CreateHeader(header)
		if err != nil {
			cleanup()
			return 0, err
		}
		if entry.path != "" {
			f, err := os.Open(entry.path)
			if err != nil {
				cleanup()
				return 0, newCLIError("ZIP_WRITE_FAILED", "failed to open restored plaintext for zip")
			}
			if _, err := io.Copy(w, f); err != nil {
				f.Close()
				cleanup()
				return 0, newCLIError("ZIP_WRITE_FAILED", "failed to stream restored plaintext into zip")
			}
			if err := f.Close(); err != nil {
				cleanup()
				return 0, newCLIError("ZIP_WRITE_FAILED", "failed to finalize restored plaintext stream")
			}
			continue
		}
		if _, err := w.Write(entry.data); err != nil {
			cleanup()
			return 0, err
		}
	}

	if err := zw.Close(); err != nil {
		cleanup()
		return 0, newCLIError("ZIP_WRITE_FAILED", "failed to finalize zip archive")
	}
	if err := tempFile.Close(); err != nil {
		_ = os.Remove(tempPath)
		return 0, newCLIError("ZIP_WRITE_FAILED", "failed to close zip archive")
	}
	if err := os.Rename(tempPath, outputPath); err != nil {
		_ = os.Remove(tempPath)
		return 0, newCLIError("ZIP_WRITE_FAILED", "failed to publish zip archive")
	}
	info, err := os.Stat(outputPath)
	if err != nil {
		return 0, newCLIError("ZIP_WRITE_FAILED", "failed to stat zip archive")
	}
	return info.Size(), nil
}

type downloadBridge struct {
	listener         net.Listener
	server           *http.Server
	baseURL          string
	downloadStarted  chan struct{}
	downloadFinished chan struct{}
	startedOnce      sync.Once
	finishedOnce     sync.Once
}

func startDownloadBridge(zipPath string) (string, *downloadBridge, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", nil, err
	}

	bridge := &downloadBridge{
		listener:         listener,
		baseURL:          "http://" + listener.Addr().String(),
		downloadStarted:  make(chan struct{}),
		downloadFinished: make(chan struct{}),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		bridge.startedOnce.Do(func() {
			close(bridge.downloadStarted)
		})
		f, err := os.Open(zipPath)
		if err != nil {
			http.Error(w, "zip not found", http.StatusNotFound)
			return
		}
		defer f.Close()
		info, err := f.Stat()
		if err != nil {
			http.Error(w, "zip unavailable", http.StatusInternalServerError)
			return
		}
		filename := filepath.Base(zipPath)
		w.Header().Set("Content-Type", "application/zip")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
		w.Header().Set("Content-Length", fmt.Sprintf("%d", info.Size()))
		w.WriteHeader(http.StatusOK)
		if _, err := io.Copy(w, f); err == nil {
			bridge.finishedOnce.Do(func() {
				close(bridge.downloadFinished)
			})
		}
	})

	bridge.server = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		_ = bridge.server.Serve(listener)
	}()

	return bridge.baseURL + "/", bridge, nil
}

func (b *downloadBridge) WaitForSingleDownload(timeout time.Duration) bool {
	if b == nil {
		return false
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case <-b.downloadFinished:
		return true
	case <-timer.C:
		return false
	}
}

func (b *downloadBridge) Close() error {
	if b == nil || b.server == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return b.server.Shutdown(ctx)
}
