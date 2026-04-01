package main

import (
	"archive/zip"
	"bytes"
	"crypto/ecdsa"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
)

func TestRunRestoreAllReportsNotImplementedForLegacyRecoveryMap(t *testing.T) {
	now := time.Date(2026, 3, 24, 0, 0, 0, 0, time.UTC)
	tempDir := t.TempDir()
	qrmPath := copyFixtureQRM(t, tempDir, "verify-legacy-map.qrm", "sample-recover-all-legacy.qrm")

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
	tempDir := t.TempDir()
	qrmPath := copyFixtureQRM(t, tempDir, "verify-plaintext-package.qrm", "sample-restore-locked.qrm")

	var stdout bytes.Buffer
	err := run([]string{"restore-all", qrmPath}, &stdout, ioDiscard{}, strings.NewReader(""), now)
	if err == nil || !strings.Contains(err.Error(), "UNSUPPORTED_SIGNER") {
		t.Fatalf("expected unsupported signer error, got %v", err)
	}
}

func TestRunRestoreAllSuccessMultiFile(t *testing.T) {
	now := time.Date(2026, 3, 24, 2, 0, 0, 0, time.UTC)
	tempDir := t.TempDir()
	privateKey := mustPrivateKey(t, "1111111111111111111111111111111111111111111111111111111111111111")
	doc := loadFixtureDoc(t, "restore-multi.qrm")
	installFixtureBlob(t, "restore-multi-1.enc", fixtureRestoreMultiSourceOne)
	installFixtureBlob(t, "restore-multi-2.enc", fixtureRestoreMultiSourceTwo)
	qrmPath := copyFixtureQRM(t, tempDir, "restore-multi.qrm", "restore-multi.qrm")

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
	doc := loadFixtureDoc(t, "restore-single.qrm")
	installFixtureBlob(t, "restore-single-source.enc", fixtureRestoreSingleSource)
	qrmPath := copyFixtureQRM(t, tempDir, "restore-single.qrm", "restore-fail-fetch.qrm")
	_ = os.Remove(fixtureRestoreSingleSource)

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
	doc := loadFixtureDoc(t, "restore-normalized-piece-url.qrm")

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

	qrmPath := copyFixtureQRM(t, tempDir, "restore-normalized-piece-url.qrm", "restore-normalized-piece-url.qrm")

	var stdout bytes.Buffer
	err := run(
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
	doc := loadFixtureDoc(t, "restore-single.qrm")
	installFixtureBlob(t, "restore-single-source.enc", fixtureRestoreSingleSource)
	qrmPath := copyFixtureQRM(t, tempDir, "restore-single.qrm", "restore-fail-decrypt.qrm")

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
	doc := loadFixtureDoc(t, "restore-traversal.qrm")
	installFixtureBlob(t, "restore-traversal.enc", fixtureRestoreTraversalSource)
	qrmPath := copyFixtureQRM(t, tempDir, "restore-traversal.qrm", "restore-traversal.qrm")

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
	doc := loadFixtureDoc(t, "restore-single.qrm")
	installFixtureBlob(t, "restore-single-source.enc", fixtureRestoreSingleSource)
	qrmPath := copyFixtureQRM(t, tempDir, "restore-single.qrm", "restore-nobrowser.qrm")

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
	doc := loadFixtureDoc(t, "restore-single.qrm")
	installFixtureBlob(t, "restore-single-source.enc", fixtureRestoreSingleSource)
	qrmPath := copyFixtureQRM(t, tempDir, "restore-single.qrm", "restore-browser.qrm")

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
	doc := loadFixtureDoc(t, "restore-single.qrm")
	installFixtureBlob(t, "restore-single-source.enc", fixtureRestoreSingleSource)
	qrmPath := copyFixtureQRM(t, tempDir, "restore-single.qrm", "no-stdin-read.qrm")

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
	doc := loadFixtureDoc(t, "restore-single.qrm")
	installFixtureBlob(t, "restore-single-source.enc", fixtureRestoreSingleSource)
	qrmPath := copyFixtureQRM(t, tempDir, "restore-single.qrm", "restore-metamask.qrm")

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
	if !found["test.txt"] {
		t.Fatalf("expected test.txt in zip, found: %v", found)
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

func buildRestoreAllStdin(t *testing.T, doc recoveryMapDocument, privateKey *ecdsa.PrivateKey, recoveryKey string) io.Reader {
	challenge, err := buildUnlockChallenge(doc)
	if err != nil {
		t.Fatalf("build challenge: %v", err)
	}
	signature := mustPersonalSign(t, privateKey, challenge)
	return strings.NewReader(signature + "\n" + recoveryKey + "\n")
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
