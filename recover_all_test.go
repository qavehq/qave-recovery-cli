package main

import (
	"archive/zip"
	"bytes"
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
)

func TestRunRestoreAllReportsNotImplementedForLegacyRecoveryMap(t *testing.T) {
	now := time.Date(2026, 3, 24, 0, 0, 0, 0, time.UTC)
	privateKey := mustPrivateKey(t, "1111111111111111111111111111111111111111111111111111111111111111")
	vaultOwner := strings.ToLower(crypto.PubkeyToAddress(privateKey.PublicKey).Hex())

	doc := buildRestorePlaintextTestDoc(t, now, vaultOwner, map[string]testRestoreFileEntry{
		"reports/file1.txt": {
			content:     []byte("test content"),
			sourcePath:  "",
			materialVer: 7,
		},
	}, privateKey)

	tempDir := t.TempDir()
	qrmPath := filepath.Join(tempDir, "sample-recover-all-legacy.qrm")
	writeTestQRM(t, qrmPath, doc)

	var stdout bytes.Buffer
	err := run([]string{"restore-all", qrmPath, "--signer", "manual"}, &stdout, ioDiscard{}, strings.NewReader("\n"), now)
	if err == nil || !strings.Contains(err.Error(), "RECOVERY_PACKAGE_REQUIRED") {
		t.Fatalf("expected recovery package required error, got %v\nstdout: %s", err, stdout.String())
	}
	if !strings.Contains(stdout.String(), "package_structure=legacy_recovery_map") {
		t.Fatalf("unexpected stdout: %s", stdout.String())
	}
}

func TestRunRestoreAllRequiresSigner(t *testing.T) {
	now := time.Date(2026, 3, 24, 1, 0, 0, 0, time.UTC)
	doc := buildPlaintextRecoveryPackageV1Sample(now)

	tempDir := t.TempDir()
	qrmPath := filepath.Join(tempDir, "sample-restore-locked.qrm")
	raw, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatalf("marshal sample: %v", err)
	}
	if err := os.WriteFile(qrmPath, append(raw, '\n'), 0o600); err != nil {
		t.Fatalf("write sample: %v", err)
	}

	var stdout bytes.Buffer
	err = run([]string{"restore-all", qrmPath}, &stdout, ioDiscard{}, strings.NewReader(""), now)
	if err == nil || !strings.Contains(err.Error(), "UNSUPPORTED_SIGNER") {
		t.Fatalf("expected unsupported signer error, got %v", err)
	}
}

func TestRunRestoreAllSuccessMultiFile(t *testing.T) {
	now := time.Date(2026, 3, 24, 2, 0, 0, 0, time.UTC)
	tempDir := t.TempDir()
	privateKey := mustPrivateKey(t, "1111111111111111111111111111111111111111111111111111111111111111")
	vaultOwner := strings.ToLower(crypto.PubkeyToAddress(privateKey.PublicKey).Hex())

	file1Content := []byte("restored file one content")
	file2Content := []byte("restored file two content here")

	file1Path := writeTestFile(t, tempDir, "src1.enc", file1Content)
	file2Path := writeTestFile(t, tempDir, "src2.enc", file2Content)

	doc, _ := buildRestoreTestDoc(t, now, vaultOwner, map[string]testRestoreFileEntry{
		"reports/file1.txt": {
			content:     file1Content,
			sourcePath:  file1Path,
			materialVer: 7,
		},
		"docs/file2.txt": {
			content:     file2Content,
			sourcePath:  file2Path,
			materialVer: 7,
		},
	}, privateKey)

	qrmPath := filepath.Join(tempDir, "restore-multi.qrm")
	writeTestQRM(t, qrmPath, doc)

	var stdout bytes.Buffer
	recoveryKey := "ABCDEFGHJKMNPQRST234"
	err := run(
		[]string{"restore-all", qrmPath, "--signer", "manual", "--no-browser"},
		&stdout,
		ioDiscard{},
		buildRestoreAllStdin(t, doc, privateKey, recoveryKey),
		now,
	)
	if err != nil {
		t.Fatalf("restore-all failed: %v\nstdout: %s", err, stdout.String())
	}

	output := stdout.String()
	for _, check := range []string{
		"challenge_verified=true",
		"payload_unlocked=true",
		"restore_all_complete=true",
		"files_restored=2",
		"zip_path=",
		"browser_download_skipped=true",
	} {
		if !strings.Contains(output, check) {
			t.Fatalf("expected output to contain %q, got:\n%s", check, output)
		}
	}

	zipPath := extractZipPath(output)
	if !strings.HasSuffix(zipPath, ".zip") {
		t.Fatalf("expected .zip suffix in %q", zipPath)
	}

	zipData, err := os.ReadFile(zipPath)
	if err != nil {
		t.Fatalf("read zip: %v", err)
	}

	zr, err := zip.NewReader(bytes.NewReader(zipData), int64(len(zipData)))
	if err != nil {
		t.Fatalf("open zip reader: %v", err)
	}

	found := make(map[string]bool)
	for _, f := range zr.File {
		found[f.Name] = true
	}
	if !found["reports/file1.txt"] {
		t.Fatalf("expected reports/file1.txt in zip, found: %v", found)
	}
	if !found["docs/file2.txt"] {
		t.Fatalf("expected docs/file2.txt in zip, found: %v", found)
	}
}

func TestRunRestoreAllFailsClosedOnFetchError(t *testing.T) {
	now := time.Date(2026, 3, 24, 3, 0, 0, 0, time.UTC)
	tempDir := t.TempDir()
	privateKey := mustPrivateKey(t, "1111111111111111111111111111111111111111111111111111111111111111")
	vaultOwner := strings.ToLower(crypto.PubkeyToAddress(privateKey.PublicKey).Hex())

	doc, sourcePaths := buildRestoreTestDoc(t, now, vaultOwner, map[string]testRestoreFileEntry{
		"missing.txt": {
			content:     []byte("x"),
			sourcePath:  filepath.Join(tempDir, "nonexistent_parent", "file.enc"),
			materialVer: 7,
		},
	}, privateKey)

	qrmPath := filepath.Join(tempDir, "restore-fail-fetch.qrm")
	writeTestQRM(t, qrmPath, doc)

	for _, sp := range sourcePaths {
		os.Remove(sp)
	}

	var stdout bytes.Buffer
	err := run(
		[]string{"restore-all", qrmPath, "--signer", "manual", "--no-browser"},
		&stdout,
		ioDiscard{},
		buildRestoreAllStdin(t, doc, privateKey, "ABCDEFGHJKMNPQRST234"),
		now,
	)
	if err == nil {
		t.Fatalf("expected restore-all to fail on fetch error, got stdout: %s", stdout.String())
	}
	if !strings.Contains(err.Error(), "FETCH_FAILED") {
		t.Fatalf("expected FETCH_FAILED error, got: %v", err)
	}
	if strings.Contains(stdout.String(), "Recovery Key incorrect. Please try again.") {
		t.Fatalf("did not expect recovery key retry message for fetch error: %s", stdout.String())
	}
	if strings.Count(stdout.String(), "Paste recovery key (hyphens/spaces optional): ") != 1 {
		t.Fatalf("expected a single recovery key prompt for fetch error, got stdout: %s", stdout.String())
	}
	if !strings.Contains(stdout.String(), "restore_all_failed=true") {
		t.Fatalf("expected restore_all_failed=true in stdout: %s", stdout.String())
	}
}

func TestRunRestoreAllNormalizesKnownProviderPieceURLHostTypo(t *testing.T) {
	now := time.Date(2026, 3, 24, 3, 30, 0, 0, time.UTC)
	tempDir := t.TempDir()
	privateKey := mustPrivateKey(t, "1111111111111111111111111111111111111111111111111111111111111111")
	vaultOwner := strings.ToLower(crypto.PubkeyToAddress(privateKey.PublicKey).Hex())

	doc, _ := buildRestoreTestDoc(t, now, vaultOwner, map[string]testRestoreFileEntry{
		"piece.txt": {
			content:     []byte("restored through normalized provider piece url"),
			materialVer: 7,
		},
	}, privateKey)

	challenge, err := buildUnlockChallenge(doc)
	if err != nil {
		t.Fatalf("build challenge: %v", err)
	}
	signature := mustPersonalSign(t, privateKey, challenge)
	key, err := deriveUnlockKey(doc, challenge, signature)
	if err != nil {
		t.Fatalf("derive key: %v", err)
	}
	payload, err := decryptPayload(doc, key)
	if err != nil {
		t.Fatalf("decrypt payload: %v", err)
	}
	payload.FileIndex[0].StorageRefs = []recoveryMapStorageRef{
		{Kind: "provider_piece_url", Value: "http://calibration-pdp.infrafolio.com/piece/test-piece"},
	}
	ciphertext, tag, err := encryptPayload(doc, payload, key)
	if err != nil {
		t.Fatalf("re-encrypt payload: %v", err)
	}
	doc.PayloadCiphertext = ciphertext
	doc.PayloadTag = tag

	originalFetchClient := fetchHTTPClient
	fetchHTTPClient = &http.Client{
		Timeout: defaultFetchHTTPTimeout,
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			if req.URL.Host != recoveryPieceHostFixed {
				t.Fatalf("expected normalized host %q, got %q", recoveryPieceHostFixed, req.URL.Host)
			}
			if req.URL.Path != "/piece/test-piece" {
				t.Fatalf("unexpected path %q", req.URL.Path)
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader("ciphertext should not decrypt")),
				Header:     make(http.Header),
				Request:    req,
			}, nil
		}),
	}
	defer func() {
		fetchHTTPClient = originalFetchClient
	}()

	qrmPath := filepath.Join(tempDir, "restore-normalized-piece-url.qrm")
	writeTestQRM(t, qrmPath, doc)

	var stdout bytes.Buffer
	err = run(
		[]string{"restore-all", qrmPath, "--signer", "manual", "--no-browser"},
		&stdout,
		ioDiscard{},
		buildRestoreAllStdin(t, doc, privateKey, "ABCDE-FGHJK-MNPQR-ST234"),
		now,
	)
	if err == nil {
		t.Fatalf("expected decrypt failure after normalized fetch, got success\nstdout: %s", stdout.String())
	}
	if strings.Contains(err.Error(), "FETCH_FAILED") {
		t.Fatalf("expected to move past original fetch host failure, got %v\nstdout: %s", err, stdout.String())
	}
	if !strings.Contains(stdout.String(), "source=provider_piece_url:http://caliberation-pdp.infrafolio.com/piece/test-piece") {
		t.Fatalf("expected normalized provider_piece_url source in stdout, got %s", stdout.String())
	}
	if !strings.Contains(err.Error(), "CIPHERTEXT_DECRYPT_FAILED") {
		t.Fatalf("expected next blocker to be decrypt failure after fetch, got %v", err)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return fn(req)
}

func TestRunRestoreAllRetriesRecoveryKeyWithoutReunlock(t *testing.T) {
	now := time.Date(2026, 3, 24, 4, 0, 0, 0, time.UTC)
	tempDir := t.TempDir()
	privateKey := mustPrivateKey(t, "1111111111111111111111111111111111111111111111111111111111111111")
	vaultOwner := strings.ToLower(crypto.PubkeyToAddress(privateKey.PublicKey).Hex())

	filePath := writeTestFile(t, tempDir, "file.enc", []byte("valid encrypted content"))

	doc, _ := buildRestoreTestDoc(t, now, vaultOwner, map[string]testRestoreFileEntry{
		"file.txt": {
			content:     []byte("valid plaintext"),
			sourcePath:  filePath,
			materialVer: 7,
		},
	}, privateKey)

	qrmPath := filepath.Join(tempDir, "restore-fail-decrypt.qrm")
	writeTestQRM(t, qrmPath, doc)

	var stdout bytes.Buffer
	err := run(
		[]string{"restore-all", qrmPath, "--signer", "manual", "--no-browser"},
		&stdout,
		ioDiscard{},
		buildRestoreAllStdin(t, doc, privateKey, "ZZZZZ77777ZZZZZ77777\nABCDEFGHJKMNPQRST234"),
		now,
	)
	if err != nil {
		t.Fatalf("expected restore-all to retry recovery key and succeed, got %v\nstdout: %s", err, stdout.String())
	}
	if strings.Count(stdout.String(), "challenge:\n") != 1 {
		t.Fatalf("expected unlock challenge to appear once, got stdout: %s", stdout.String())
	}
	if strings.Count(stdout.String(), "challenge_verified=true") != 1 {
		t.Fatalf("expected challenge_verified=true once, got stdout: %s", stdout.String())
	}
	if strings.Count(stdout.String(), "payload_unlocked=true") != 1 {
		t.Fatalf("expected payload_unlocked=true once, got stdout: %s", stdout.String())
	}
	if strings.Count(stdout.String(), "Paste recovery key (hyphens/spaces optional): ") != 2 {
		t.Fatalf("expected two recovery key prompts, got stdout: %s", stdout.String())
	}
	if strings.Count(stdout.String(), "Recovery Key incorrect. Please try again.") != 1 {
		t.Fatalf("expected one recovery key retry message, got stdout: %s", stdout.String())
	}
	if !strings.Contains(stdout.String(), "restore_all_complete=true") {
		t.Fatalf("expected restore_all_complete=true after retry, got stdout: %s", stdout.String())
	}
}

func TestRunRestoreAllPathTraversalProtection(t *testing.T) {
	now := time.Date(2026, 3, 24, 5, 0, 0, 0, time.UTC)
	tempDir := t.TempDir()
	privateKey := mustPrivateKey(t, "1111111111111111111111111111111111111111111111111111111111111111")
	vaultOwner := strings.ToLower(crypto.PubkeyToAddress(privateKey.PublicKey).Hex())

	safePath := writeTestFile(t, tempDir, "safe.enc", []byte("safe content"))

	doc, _ := buildRestoreTestDoc(t, now, vaultOwner, map[string]testRestoreFileEntry{
		"docs/../../../etc/passwd": {
			content:     []byte("safe content"),
			sourcePath:  safePath,
			materialVer: 7,
		},
	}, privateKey)

	qrmPath := filepath.Join(tempDir, "restore-traversal.qrm")
	writeTestQRM(t, qrmPath, doc)

	var stdout bytes.Buffer
	recoveryKey := "ABCDEFGHJKMNPQRST234"
	err := run(
		[]string{"restore-all", qrmPath, "--signer", "manual", "--no-browser"},
		&stdout,
		ioDiscard{},
		buildRestoreAllStdin(t, doc, privateKey, recoveryKey),
		now,
	)
	if err != nil {
		t.Fatalf("restore-all failed for path traversal input: %v", err)
	}

	zipPath := extractZipPath(stdout.String())

	zipData, err := os.ReadFile(zipPath)
	if err != nil {
		t.Fatalf("read zip: %v", err)
	}

	zr, err := zip.NewReader(bytes.NewReader(zipData), int64(len(zipData)))
	if err != nil {
		t.Fatalf("open zip reader: %v", err)
	}

	for _, f := range zr.File {
		if strings.HasPrefix(f.Name, "..") || strings.HasPrefix(f.Name, "/") || strings.Contains(f.Name, "..") {
			t.Fatalf("path traversal escaped into zip: entry=%q", f.Name)
		}
	}
}

func TestRunRestoreAllNoBrowserFlag(t *testing.T) {
	now := time.Date(2026, 3, 24, 6, 0, 0, 0, time.UTC)
	tempDir := t.TempDir()
	privateKey := mustPrivateKey(t, "1111111111111111111111111111111111111111111111111111111111111111")
	vaultOwner := strings.ToLower(crypto.PubkeyToAddress(privateKey.PublicKey).Hex())

	filePath := writeTestFile(t, tempDir, "test.enc", []byte("content"))

	doc, _ := buildRestoreTestDoc(t, now, vaultOwner, map[string]testRestoreFileEntry{
		"test.txt": {
			content:     []byte("content"),
			sourcePath:  filePath,
			materialVer: 7,
		},
	}, privateKey)

	qrmPath := filepath.Join(tempDir, "restore-nobrowser.qrm")
	writeTestQRM(t, qrmPath, doc)

	var stdout bytes.Buffer
	err := run(
		[]string{"restore-all", qrmPath, "--signer", "manual", "--no-browser"},
		&stdout,
		ioDiscard{},
		buildRestoreAllStdin(t, doc, privateKey, "ABCDEFGHJKMNPQRST234"),
		now,
	)
	if err != nil {
		t.Fatalf("restore-all --no-browser failed: %v", err)
	}
	output := stdout.String()
	if !strings.Contains(output, "browser_download_skipped=true") {
		t.Fatalf("expected browser_download_skipped=true, got: %s", output)
	}
	if strings.Contains(output, "download_url=") {
		t.Fatalf("expected no download_url with --no-browser, got: %s", output)
	}
}

func TestRunRestoreAllBrowserBridgeWaitsForDownload(t *testing.T) {
	now := time.Date(2026, 3, 24, 6, 30, 0, 0, time.UTC)
	tempDir := t.TempDir()
	privateKey := mustPrivateKey(t, "1111111111111111111111111111111111111111111111111111111111111111")
	vaultOwner := strings.ToLower(crypto.PubkeyToAddress(privateKey.PublicKey).Hex())

	filePath := writeTestFile(t, tempDir, "test.enc", []byte("content"))
	doc, _ := buildRestoreTestDoc(t, now, vaultOwner, map[string]testRestoreFileEntry{
		"test.txt": {
			content:     []byte("content"),
			sourcePath:  filePath,
			materialVer: 7,
		},
	}, privateKey)

	qrmPath := filepath.Join(tempDir, "restore-browser.qrm")
	writeTestQRM(t, qrmPath, doc)

	previousOpenBrowser := openBrowserURL
	openBrowserURL = func(target string) error {
		go func() {
			resp, err := http.Get(target)
			if err == nil {
				_, _ = io.ReadAll(resp.Body)
				resp.Body.Close()
			}
		}()
		return nil
	}
	defer func() {
		openBrowserURL = previousOpenBrowser
	}()

	var stdout bytes.Buffer
	err := run(
		[]string{"restore-all", qrmPath, "--signer", "manual"},
		&stdout,
		ioDiscard{},
		buildRestoreAllStdin(t, doc, privateKey, "ABCDEFGHJKMNPQRST234"),
		now,
	)
	if err != nil {
		t.Fatalf("restore-all with browser bridge failed: %v\nstdout: %s", err, stdout.String())
	}

	output := stdout.String()
	if !strings.Contains(output, "browser_opened=true") {
		t.Fatalf("expected browser_opened=true, got: %s", output)
	}
	if !strings.Contains(output, "browser_download_completed=true") {
		t.Fatalf("expected browser_download_completed=true, got: %s", output)
	}

	zipPath := extractZipPath(output)
	if _, err := os.Stat(zipPath); err != nil {
		t.Fatalf("expected zip to remain on disk after bridge download, got %v", err)
	}
}

func TestRunRestoreAllMetamaskSignerDoesNotReadStdinForSignature(t *testing.T) {
	now := time.Date(2026, 3, 24, 5, 0, 0, 0, time.UTC)
	tempDir := t.TempDir()
	privateKey := mustPrivateKey(t, "1111111111111111111111111111111111111111111111111111111111111111")
	vaultOwner := strings.ToLower(crypto.PubkeyToAddress(privateKey.PublicKey).Hex())

	filePath := writeTestFile(t, tempDir, "source.enc", []byte("content"))

	doc, _ := buildRestoreTestDoc(t, now, vaultOwner, map[string]testRestoreFileEntry{
		"test.txt": {
			content:     []byte("content"),
			sourcePath:  filePath,
			materialVer: 7,
		},
	}, privateKey)

	qrmPath := filepath.Join(tempDir, "no-stdin-read.qrm")
	writeTestQRM(t, qrmPath, doc)

	var stdout bytes.Buffer
	stdinRead, stdinWrite, err := os.Pipe()
	if err != nil {
		t.Fatalf("create stdin pipe: %v", err)
	}
	defer stdinRead.Close()
	defer stdinWrite.Close()

	doneReadingStdin := make(chan struct{})
	go func() {
		buf := make([]byte, 1)
		n, _ := stdinRead.Read(buf)
		if n > 0 {
			close(doneReadingStdin)
		}
	}()

	runErr := make(chan error, 1)
	go func() {
		runErr <- run(
			[]string{"restore-all", qrmPath, "--signer", "metamask", "--no-browser"},
			&stdout,
			ioDiscard{},
			stdinRead,
			now,
		)
	}()

	select {
	case <-doneReadingStdin:
		t.Fatalf("restore-all with metamask signer read from stdin BEFORE opening loopback bridge — this means stdin was consumed for signature reading, which is the bug")
	case <-time.After(2 * time.Second):
	}

	challenge, _ := buildUnlockChallenge(doc)

	callbackDone := make(chan struct{})
	sessionID := ""
	bridgeBase := ""
	go func() {
		ticker := time.NewTicker(5 * time.Millisecond)
		defer ticker.Stop()
		deadline := time.After(5 * time.Second)
		for {
			select {
			case <-callbackDone:
				return
			case <-deadline:
				return
			case <-ticker.C:
				output := stdout.String()
				idx := strings.Index(output, "sign_url=http://")
				if idx == -1 {
					continue
				}
				lineEnd := strings.Index(output[idx:], "\n")
				if lineEnd == -1 {
					lineEnd = len(output) - idx
				} else {
					lineEnd += idx
				}
				signURL := output[idx:lineEnd]
				if !strings.Contains(signURL, "/sign?session=") {
					continue
				}
				signStart := strings.Index(signURL, "http://")
				if signStart == -1 {
					continue
				}
				signURLOnly := signURL[signStart:]
				sessionIdx := strings.Index(signURLOnly, "session=")
				if sessionIdx == -1 {
					continue
				}
				sessionID = signURLOnly[sessionIdx+len("session="):]
				bridgeBase = signURLOnly[:strings.Index(signURLOnly, "/sign?session=")]
				signature := mustPersonalSign(t, privateKey, challenge)
				cbBody, _ := json.Marshal(map[string]string{
					"session_id": sessionID,
					"address":    strings.ToLower(crypto.PubkeyToAddress(privateKey.PublicKey).Hex()),
					"signature":  signature,
				})
				http.Post(bridgeBase+"/callback", "application/json", bytes.NewReader(cbBody))
				close(callbackDone)
				return
			}
		}
	}()

	<-callbackDone

	time.Sleep(50 * time.Millisecond)
	_, err = stdinWrite.Write([]byte("ABCDE FGHJK MNPQR ST234\n"))
	if err != nil {
		runErr <- err
		return
	}
	stdinWrite.Close()

	select {
	case err := <-runErr:
		errStr := err.Error()
		if strings.Contains(errStr, "USAGE") && strings.Contains(errStr, "stdin must contain signature") {
			t.Fatalf("BUG NOT FIXED: restore-all with --signer metamask incorrectly required stdin signature before loopback bridge. This means the stdin read happened before the signer branch.")
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("restore-all timed out\nstdout: %s", stdout.String())
	}

	output := stdout.String()
	if strings.Contains(output, "USAGE") && strings.Contains(output, "stdin must contain signature") {
		t.Fatalf("BUG NOT FIXED: restore-all with metamask signer incorrectly required stdin signature")
	}
	if !strings.Contains(output, "signer=metamask") {
		t.Fatalf("expected signer=metamask in output: %s", output)
	}
	if !strings.Contains(output, "sign_url=") {
		t.Fatalf("expected sign_url in output (loopback bridge should be started): %s", output)
	}
	if !strings.Contains(output, "challenge_verified=true") {
		t.Fatalf("expected challenge_verified=true in output: %s", output)
	}
	if !strings.Contains(output, "payload_unlocked=true") {
		t.Fatalf("expected payload_unlocked=true in output: %s", output)
	}
}

func TestRunRestoreAllMetamaskSigner(t *testing.T) {
	now := time.Date(2026, 3, 24, 5, 0, 0, 0, time.UTC)
	tempDir := t.TempDir()
	privateKey := mustPrivateKey(t, "1111111111111111111111111111111111111111111111111111111111111111")
	vaultOwner := strings.ToLower(crypto.PubkeyToAddress(privateKey.PublicKey).Hex())

	fileContent := []byte("metamask-restored content")
	filePath := writeTestFile(t, tempDir, "secret.enc", fileContent)

	doc, _ := buildRestoreTestDoc(t, now, vaultOwner, map[string]testRestoreFileEntry{
		"secret.txt": {
			content:     fileContent,
			sourcePath:  filePath,
			materialVer: 7,
		},
	}, privateKey)

	qrmPath := filepath.Join(tempDir, "restore-metamask.qrm")
	writeTestQRM(t, qrmPath, doc)

	var stdout bytes.Buffer
	recoveryKey := "ABCDEFGHJKMNPQRST234"

	stdinRead, stdinWrite, err := os.Pipe()
	if err != nil {
		t.Fatalf("create stdin pipe: %v", err)
	}
	defer stdinRead.Close()
	defer stdinWrite.Close()

	runErr := make(chan error, 1)
	go func() {
		runErr <- run(
			[]string{"restore-all", qrmPath, "--signer", "metamask", "--no-browser"},
			&stdout,
			ioDiscard{},
			stdinRead,
			now,
		)
	}()

	challenge, _ := buildUnlockChallenge(doc)

	callbackDone := make(chan struct{})
	sessionID := ""
	bridgeBase := ""
	go func() {
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
		deadline := time.After(5 * time.Second)
		for {
			select {
			case <-callbackDone:
				return
			case <-deadline:
				return
			case <-ticker.C:
				output := stdout.String()
				idx := strings.Index(output, "sign_url=http://")
				if idx == -1 {
					continue
				}
				lineEnd := strings.Index(output[idx:], "\n")
				if lineEnd == -1 {
					lineEnd = len(output) - idx
				} else {
					lineEnd += idx
				}
				signURL := output[idx:lineEnd]
				if !strings.Contains(signURL, "/sign?session=") {
					continue
				}
				signStart := strings.Index(signURL, "http://")
				if signStart == -1 {
					continue
				}
				signURLOnly := signURL[signStart:]
				sessionIdx := strings.Index(signURLOnly, "session=")
				if sessionIdx == -1 {
					continue
				}
				sessionID = signURLOnly[sessionIdx+len("session="):]
				bridgeBase = signURLOnly[:strings.Index(signURLOnly, "/sign?session=")]
				signature := mustPersonalSign(t, privateKey, challenge)
				cbBody, _ := json.Marshal(map[string]string{
					"session_id": sessionID,
					"address":    strings.ToLower(crypto.PubkeyToAddress(privateKey.PublicKey).Hex()),
					"signature":  signature,
				})
				http.Post(bridgeBase+"/callback", "application/json", bytes.NewReader(cbBody))
				close(callbackDone)
				return
			}
		}
	}()

	<-callbackDone

	time.Sleep(50 * time.Millisecond)
	_, err = stdinWrite.Write([]byte(recoveryKey + "\n"))
	if err != nil {
		runErr <- err
		return
	}
	stdinWrite.Close()

	select {
	case err := <-runErr:
		if err != nil {
			t.Fatalf("restore-all with metamask signer failed: %v\nstdout: %s", err, stdout.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("restore-all timed out\nstdout: %s", stdout.String())
	}

	output := stdout.String()
	for _, check := range []string{
		"signer=metamask",
		"sign_url=",
		"challenge_verified=true",
		"payload_unlocked=true",
		"restore_all_complete=true",
		"files_restored=1",
		"browser_download_skipped=true",
	} {
		if !strings.Contains(output, check) {
			t.Fatalf("expected output to contain %q, got:\n%s", check, output)
		}
	}

	zipPath := extractZipPath(output)
	zipData, err := os.ReadFile(zipPath)
	if err != nil {
		t.Fatalf("read zip: %v", err)
	}
	zr, err := zip.NewReader(bytes.NewReader(zipData), int64(len(zipData)))
	if err != nil {
		t.Fatalf("open zip reader: %v", err)
	}
	found := make(map[string]bool)
	for _, f := range zr.File {
		found[f.Name] = true
	}
	if !found["secret.txt"] {
		t.Fatalf("expected secret.txt in zip, found: %v", found)
	}
}

func TestSanitizeZipRelativePath(t *testing.T) {
	cases := []struct {
		input    string
		index    int
		wantSafe bool
	}{
		{"reports/alpha.txt", 0, true},
		{"docs/beta.bin", 1, true},
		{"file.txt", 2, true},
		{"", 3, true},
		{"../../../etc/passwd", 4, true},
		{"docs/../../etc/passwd", 5, true},
		{"/etc/passwd", 6, true},
	}
	for _, tc := range cases {
		got := sanitizeZipRelativePath(tc.input, tc.index)
		isSafe := !strings.HasPrefix(got, "..") && !strings.HasPrefix(got, "/")
		if isSafe != tc.wantSafe {
			t.Fatalf("sanitizeZipRelativePath(%q, %d) = %q; isSafe=%v wantSafe=%v",
				tc.input, tc.index, got, isSafe, tc.wantSafe)
		}
	}
}

func TestBuildRestoreZipContainsManifest(t *testing.T) {
	now := time.Date(2026, 3, 24, 7, 0, 0, 0, time.UTC)
	tempDir := t.TempDir()
	alphaPath := filepath.Join(tempDir, "alpha.txt")
	betaPath := filepath.Join(tempDir, "docs", "beta.bin")
	if err := os.MkdirAll(filepath.Dir(betaPath), 0o755); err != nil {
		t.Fatalf("mkdir beta dir: %v", err)
	}
	if err := os.WriteFile(alphaPath, []byte("content a"), 0o600); err != nil {
		t.Fatalf("write alpha: %v", err)
	}
	if err := os.WriteFile(betaPath, []byte("content b"), 0o600); err != nil {
		t.Fatalf("write beta: %v", err)
	}
	entries := []restoredFile{
		{name: "alpha.txt", path: alphaPath},
		{name: "docs/beta.bin", path: betaPath},
	}
	doc := recoveryMapDocument{
		Header: recoveryMapHeader{
			Schema:         recoveryMapSchema,
			MapID:          "test-map",
			GeneratedAt:    now.Format(time.RFC3339Nano),
			VaultOwner:     "0x123400000000000000000000000000000000abcd",
			VaultStateHash: strings.Repeat("a", 64),
		},
	}

	zipPath := filepath.Join(tempDir, "restore.zip")
	zipSize, err := writeRestoreZip(zipPath, entries, doc, now)
	if err != nil {
		t.Fatalf("writeRestoreZip: %v", err)
	}
	zipBytes, err := os.ReadFile(zipPath)
	if err != nil {
		t.Fatalf("read zip: %v", err)
	}
	if zipSize != int64(len(zipBytes)) {
		t.Fatalf("expected zip size %d, got %d", len(zipBytes), zipSize)
	}

	zr, err := zip.NewReader(bytes.NewReader(zipBytes), int64(len(zipBytes)))
	if err != nil {
		t.Fatalf("zip.NewReader: %v", err)
	}

	foundManifest, foundAlpha, foundBeta := false, false, false
	for _, f := range zr.File {
		if f.Name == "manifest.json" {
			foundManifest = true
			rc, err := f.Open()
			if err != nil {
				t.Fatalf("open manifest: %v", err)
			}
			var manifest map[string]any
			if err := json.NewDecoder(rc).Decode(&manifest); err != nil {
				t.Fatalf("decode manifest: %v", err)
			}
			rc.Close()
			if manifest["files_restored"].(float64) != 2 {
				t.Fatalf("expected files_restored=2, got %v", manifest)
			}
		}
		if f.Name == "alpha.txt" {
			foundAlpha = true
		}
		if f.Name == "docs/beta.bin" {
			foundBeta = true
		}
	}
	if !foundManifest {
		t.Fatalf("zip missing manifest.json")
	}
	if !foundAlpha {
		t.Fatalf("zip missing alpha.txt")
	}
	if !foundBeta {
		t.Fatalf("zip missing docs/beta.bin")
	}
}

func TestDownloadBridgeServesZip(t *testing.T) {
	tempDir := t.TempDir()
	zipPath := filepath.Join(tempDir, "test.zip")

	zipData := []byte("PK\x03\x04test content")
	if err := os.WriteFile(zipPath, zipData, 0o600); err != nil {
		t.Fatalf("write zip: %v", err)
	}

	downloadURL, bridge, err := startDownloadBridge(zipPath)
	if err != nil {
		t.Fatalf("startDownloadBridge: %v", err)
	}
	defer bridge.Close()

	resp, err := http.Get(downloadURL)
	if err != nil {
		t.Fatalf("GET download URL: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/zip" {
		t.Fatalf("expected application/zip, got %s", ct)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if string(body) != string(zipData) {
		t.Fatalf("expected zip data, got different content")
	}
	if !bridge.WaitForSingleDownload(time.Second) {
		t.Fatalf("expected bridge to observe a completed download")
	}
	if _, err := os.Stat(zipPath); err != nil {
		t.Fatalf("expected zip to remain on disk after bridge use, got %v", err)
	}
}

type testRestoreFileEntry struct {
	content     []byte
	sourcePath  string
	materialVer int
}

func buildRestoreTestDoc(t *testing.T, now time.Time, vaultOwner string, files map[string]testRestoreFileEntry, privateKey *ecdsa.PrivateKey) (recoveryMapDocument, []string) {
	t.Helper()

	fileKeyBytes := bytes.Repeat([]byte{0x21}, fileKeyLengthBytes)
	wrapIV := bytes.Repeat([]byte{0x56}, wrapIVLengthBytes)
	contentIV := bytes.Repeat([]byte{0x34}, wrapIVLengthBytes)
	saltBytes := bytes.Repeat([]byte{0x78}, 16)

	recoveryKey := "ABCDEFGHJKMNPQRST234"
	wrapKeyBytes, err := deriveRecoveryWrapKeyBytes(recoveryKey, recoveryPackageKDFProfile{
		MaterialVersion: 7,
		KDFAlgorithm:    recoveryKDFAlgorithmPBKDF2SHA256,
		KDFSalt:         base64.StdEncoding.EncodeToString(saltBytes),
		KDFParams: recoveryPackageKDFParams{
			Iterations:       600000,
			Hash:             recoveryKDFHashSHA256,
			DerivedKeyLength: recoveryDerivedKeyLengthBytes,
		},
		KDFVersion: recoveryKDFVersion1,
	})
	if err != nil {
		t.Fatalf("derive wrap key: %v", err)
	}
	defer zeroBytes(wrapKeyBytes)

	matVersion := 7
	kdfAlg := recoveryKDFAlgorithmPBKDF2SHA256
	wrapAlg := recoveryWrapAlgorithmAES256GCM
	wrapIVB64 := base64.StdEncoding.EncodeToString(wrapIV)

	i := 0
	fileIndex := make([]recoveryMapFileIndex, 0, len(files))
	fetchSources := make([]recoveryPackageFetchSource, 0, len(files))
	wrappedKeys := make([]recoveryPackageWrappedKey, 0, len(files))
	sourcePaths := make([]string, 0)

	for name, entry := range files {
		mv := entry.materialVer
		if mv == 0 {
			mv = 7
		}

		ciphertext := mustSealAESGCM(t, fileKeyBytes, contentIV, entry.content)

		if entry.sourcePath != "" {
			if err := os.MkdirAll(filepath.Dir(entry.sourcePath), 0o700); err != nil {
				t.Fatalf("create source dir: %v", err)
			}
			if err := os.WriteFile(entry.sourcePath, ciphertext, 0o600); err != nil {
				t.Fatalf("write source: %v", err)
			}
			sourcePaths = append(sourcePaths, entry.sourcePath)
		}

		wrappedFileKey := mustSealAESGCM(t, wrapKeyBytes, wrapIV, fileKeyBytes)
		wrappedB64 := base64.StdEncoding.EncodeToString(wrappedFileKey)
		contentIVB64 := base64.StdEncoding.EncodeToString(contentIV)

		fileID := fmt.Sprintf("00000000-0000-4000-8000-%012d", i+1)

		fileIndex = append(fileIndex, recoveryMapFileIndex{
			FileID:      fileID,
			FileName:    filepath.Base(name),
			LogicalPath: name,
			Name:        name,
			Size:        int64(len(entry.content)),
			CID:         "",
			StorageRefs: []recoveryMapStorageRef{
				{Kind: "provider_operation_ref", Value: (&url.URL{Scheme: "file", Path: entry.sourcePath}).String()},
			},
			UploadedAt:    now.Format(time.RFC3339Nano),
			SnapshotIndex: i,
			ExpiresAt:     "2099-01-01T00:00:00Z",
			Status:        "stored",
			Encryption: recoveryMapFileEncryption{
				Mode:                "phase1-transport-schema-only",
				KeyMaterialIncluded: false,
				KeyDerivation:       "phase2-wallet-bound-hkdf-reserved",
				WalletBinding:       "not_included_in_phase1",
			},
			ContentEncryption: &recoveryPackageContentEncryption{
				EncryptionVersion:          1,
				ContentEncryptionAlgorithm: recoveryWrapAlgorithmAES256GCM,
				ContentEncryptionIV:        contentIVB64,
			},
			RecoveryMaterialVersion: &mv,
		})

		fetchSources = append(fetchSources, recoveryPackageFetchSource{
			FileID:                 fileID,
			SourceType:             "provider_operation_ref",
			SourceRef:              entry.sourcePath,
			FetchCapabilityVersion: "qave.recovery-fetch.v1",
		})
		wrappedKeys = append(wrappedKeys, recoveryPackageWrappedKey{
			FileID:                  fileID,
			RecoveryMaterialVersion: &mv,
			WrappedFileKey:          &wrappedB64,
			KeyWrapAlgorithm:        &wrapAlg,
			KeyWrapVersion:          recoveryWrapVersion1,
			IV:                      &wrapIVB64,
			KeyMaterialVersion:      recoveryKeyMaterialVersion1,
		})
		i++
	}

	payload := recoveryMapPayload{
		Snapshot: &recoveryPackageSnapshot{
			SchemaVersion:         recoveryPackageSchemaVersion,
			PackageID:             "test-restore-package",
			MapID:                 "test-restore-package",
			VaultOwner:            vaultOwner,
			VaultStateHash:        strings.Repeat("a", 64),
			GeneratedAt:           now.Format(time.RFC3339Nano),
			SubscriptionExpiresAt: "2099-01-01T00:00:00Z",
			FileCount:             len(fileIndex),
			PackageProtectionMode: payloadProtectionWalletBoundEncrypted,
			RecoveryFlowVersion:   "recover-all.v1",
			RecoveryKDFProfiles: []recoveryPackageKDFProfile{
				{
					MaterialVersion: matVersion,
					KDFAlgorithm:    kdfAlg,
					KDFSalt:         base64.StdEncoding.EncodeToString(saltBytes),
					KDFParams: recoveryPackageKDFParams{
						Iterations:       600000,
						Hash:             recoveryKDFHashSHA256,
						DerivedKeyLength: recoveryDerivedKeyLengthBytes,
					},
					KDFVersion: recoveryKDFVersion1,
				},
			},
		},
		FileIndex:    fileIndex,
		FetchSources: fetchSources,
		WrappedKeys:  wrappedKeys,
		RecoveryPolicy: &recoveryPackageRecoveryPolicy{
			RequiresWalletAuth:     true,
			RequiresRecoveryKey:    true,
			TrustedDeviceSupported: false,
			RecoverAllMode:         "batch_only",
			LocalDecryptRequired:   true,
			LocalPackageRequired:   true,
		},
		FWSSNetwork:    "phase2-reserved",
		FWSSAPIVersion: "v1",
	}

	doc := recoveryMapDocument{
		Header: recoveryMapHeader{
			Schema:                recoveryMapSchema,
			MapID:                 "test-restore-package",
			GeneratedAt:           now.Format(time.RFC3339Nano),
			VaultOwner:            vaultOwner,
			VaultStateHash:        strings.Repeat("a", 64),
			SubscriptionExpiresAt: "2099-01-01T00:00:00Z",
			PayloadEncryption: recoveryPayloadEncryption{
				Algorithm:         "AES-256-GCM",
				KDF:               "HKDF-SHA256",
				Nonce:             "MDEyMzQ1Njc4OWFi",
				Binding:           "wallet_bound_personal_sign_v1",
				PayloadProtection: payloadProtectionWalletBoundEncrypted,
				Encoding:          "base64",
				SigningScope:      signingScopeLegacyPerExport,
			},
		},
	}

	challenge, err := buildUnlockChallenge(doc)
	if err != nil {
		t.Fatalf("build challenge: %v", err)
	}
	signature := mustPersonalSign(t, privateKey, challenge)
	key, err := deriveUnlockKey(doc, challenge, signature)
	if err != nil {
		t.Fatalf("derive key: %v", err)
	}
	ciphertext, tag, err := encryptPayload(doc, payload, key)
	if err != nil {
		t.Fatalf("encrypt payload: %v", err)
	}
	doc.PayloadCiphertext = ciphertext
	doc.PayloadTag = tag

	return doc, sourcePaths
}

func buildRestoreAllStdin(t *testing.T, doc recoveryMapDocument, privateKey *ecdsa.PrivateKey, recoveryKey string) io.Reader {
	challenge, err := buildUnlockChallenge(doc)
	if err != nil {
		t.Fatalf("build challenge: %v", err)
	}
	signature := mustPersonalSign(t, privateKey, challenge)
	return strings.NewReader(signature + "\n" + recoveryKey + "\n")
}

func buildRestorePlaintextTestDoc(t *testing.T, now time.Time, vaultOwner string, files map[string]testRestoreFileEntry, privateKey *ecdsa.PrivateKey) recoveryMapDocument {
	t.Helper()

	fileKeyBytes := bytes.Repeat([]byte{0x21}, fileKeyLengthBytes)
	wrapIV := bytes.Repeat([]byte{0x56}, wrapIVLengthBytes)
	contentIV := bytes.Repeat([]byte{0x34}, wrapIVLengthBytes)
	saltBytes := bytes.Repeat([]byte{0x78}, 16)

	matVersion := 7
	wrapAlg := recoveryWrapAlgorithmAES256GCM
	wrapIVB64 := base64.StdEncoding.EncodeToString(wrapIV)
	contentIVB64 := base64.StdEncoding.EncodeToString(contentIV)

	i := 0
	fileIndex := make([]recoveryMapFileIndex, 0, len(files))
	fetchSources := make([]recoveryPackageFetchSource, 0, len(files))
	wrappedKeys := make([]recoveryPackageWrappedKey, 0, len(files))

	for name, entry := range files {
		mv := entry.materialVer
		if mv == 0 {
			mv = 7
		}

		ciphertext := mustSealAESGCM(t, fileKeyBytes, contentIV, entry.content)

		if entry.sourcePath != "" {
			if err := os.MkdirAll(filepath.Dir(entry.sourcePath), 0o700); err != nil {
				t.Fatalf("create source dir: %v", err)
			}
			if err := os.WriteFile(entry.sourcePath, ciphertext, 0o600); err != nil {
				t.Fatalf("write source: %v", err)
			}
		}

		wrappedFileKey := mustSealAESGCM(t, bytes.Repeat([]byte{0xAB}, 32), wrapIV, fileKeyBytes)
		wrappedB64 := base64.StdEncoding.EncodeToString(wrappedFileKey)

		fileID := fmt.Sprintf("00000000-0000-4000-8000-%012d", i+1)

		fileIndex = append(fileIndex, recoveryMapFileIndex{
			FileID:      fileID,
			FileName:    filepath.Base(name),
			LogicalPath: name,
			Name:        name,
			Size:        int64(len(entry.content)),
			CID:         "",
			StorageRefs: []recoveryMapStorageRef{
				{Kind: "provider_operation_ref", Value: (&url.URL{Scheme: "file", Path: entry.sourcePath}).String()},
			},
			UploadedAt:    now.Format(time.RFC3339Nano),
			SnapshotIndex: i,
			ExpiresAt:     "2099-01-01T00:00:00Z",
			Status:        "stored",
			Encryption: recoveryMapFileEncryption{
				Mode:                "phase1-transport-schema-only",
				KeyMaterialIncluded: false,
				KeyDerivation:       "phase2-wallet-bound-hkdf-reserved",
				WalletBinding:       "not_included_in_phase1",
			},
			ContentEncryption: &recoveryPackageContentEncryption{
				EncryptionVersion:          1,
				ContentEncryptionAlgorithm: recoveryWrapAlgorithmAES256GCM,
				ContentEncryptionIV:        contentIVB64,
			},
			RecoveryMaterialVersion: &mv,
		})

		fetchSources = append(fetchSources, recoveryPackageFetchSource{
			FileID:                 fileID,
			SourceType:             "provider_operation_ref",
			SourceRef:              entry.sourcePath,
			FetchCapabilityVersion: "qave.recovery-fetch.v1",
		})
		wrappedKeys = append(wrappedKeys, recoveryPackageWrappedKey{
			FileID:                  fileID,
			RecoveryMaterialVersion: &mv,
			WrappedFileKey:          &wrappedB64,
			KeyWrapAlgorithm:        &wrapAlg,
			KeyWrapVersion:          recoveryWrapVersion1,
			IV:                      &wrapIVB64,
			KeyMaterialVersion:      recoveryKeyMaterialVersion1,
		})
		i++
	}

	payload := recoveryMapPayload{
		Snapshot: &recoveryPackageSnapshot{
			SchemaVersion:         recoveryPackageSchemaVersion,
			PackageID:             "test-restore-package",
			MapID:                 "test-restore-package",
			VaultOwner:            vaultOwner,
			VaultStateHash:        strings.Repeat("a", 64),
			GeneratedAt:           now.Format(time.RFC3339Nano),
			SubscriptionExpiresAt: "2099-01-01T00:00:00Z",
			FileCount:             len(fileIndex),
			PackageProtectionMode: payloadProtectionLegacyPlaintext,
			RecoveryFlowVersion:   "recover-all.v1",
			RecoveryKDFProfiles: []recoveryPackageKDFProfile{
				{
					MaterialVersion: matVersion,
					KDFAlgorithm:    recoveryKDFAlgorithmPBKDF2SHA256,
					KDFSalt:         base64.StdEncoding.EncodeToString(saltBytes),
					KDFParams: recoveryPackageKDFParams{
						Iterations:       600000,
						Hash:             recoveryKDFHashSHA256,
						DerivedKeyLength: recoveryDerivedKeyLengthBytes,
					},
					KDFVersion: recoveryKDFVersion1,
				},
			},
		},
		FileIndex:    fileIndex,
		FetchSources: fetchSources,
		WrappedKeys:  wrappedKeys,
		RecoveryPolicy: &recoveryPackageRecoveryPolicy{
			RequiresWalletAuth:     true,
			RequiresRecoveryKey:    true,
			TrustedDeviceSupported: false,
			RecoverAllMode:         "batch_only",
			LocalDecryptRequired:   true,
			LocalPackageRequired:   true,
		},
		FWSSNetwork:    "phase2-reserved",
		FWSSAPIVersion: "v1",
	}

	return recoveryMapDocument{
		Header: recoveryMapHeader{
			Schema:                recoveryMapSchema,
			MapID:                 "test-restore-package",
			GeneratedAt:           now.Format(time.RFC3339Nano),
			VaultOwner:            vaultOwner,
			VaultStateHash:        strings.Repeat("a", 64),
			SubscriptionExpiresAt: "2099-01-01T00:00:00Z",
			PayloadEncryption: recoveryPayloadEncryption{
				Algorithm:         "AES-256-GCM",
				KDF:               "HKDF-SHA256",
				Nonce:             "MDEyMzQ1Njc4OWFi",
				Binding:           "wallet_bound_personal_sign_v1",
				PayloadProtection: payloadProtectionLegacyPlaintext,
				Encoding:          "base64",
				SigningScope:      signingScopeLegacyPerExport,
			},
		},
		Payload: &payload,
	}
}

func writeTestFile(t *testing.T, tempDir, name string, content []byte) string {
	t.Helper()
	path := filepath.Join(tempDir, name)
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("write test file: %v", err)
	}
	return path
}

func writeTestQRM(t *testing.T, qrmPath string, doc recoveryMapDocument) {
	t.Helper()
	raw, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatalf("marshal qrm: %v", err)
	}
	if err := os.WriteFile(qrmPath, append(raw, '\n'), 0o600); err != nil {
		t.Fatalf("write qrm: %v", err)
	}
}

func extractZipPath(output string) string {
	start := strings.Index(output, "zip_path=")
	if start < 0 {
		return ""
	}
	line := output[start:]
	line = line[:strings.Index(line, "\n")]
	return strings.TrimSpace(strings.TrimPrefix(line, "zip_path="))
}
