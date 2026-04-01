package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
)

func TestSelectRecoveryFileByNameCIDIndex(t *testing.T) {
	payload := recoveryMapPayload{
		FileIndex: []recoveryMapFileIndex{
			{Name: "alpha.txt", CID: "cid-alpha"},
			{Name: "docs/beta.txt", CID: "cid-beta"},
		},
	}

	byName, err := selectRecoveryFile(payload, "docs/beta.txt")
	if err != nil {
		t.Fatalf("select by name: %v", err)
	}
	if byName.index != 1 {
		t.Fatalf("expected index 1, got %d", byName.index)
	}

	byCID, err := selectRecoveryFile(payload, "cid-alpha")
	if err != nil {
		t.Fatalf("select by cid: %v", err)
	}
	if byCID.index != 0 {
		t.Fatalf("expected index 0, got %d", byCID.index)
	}

	byIndex, err := selectRecoveryFile(payload, "2")
	if err != nil {
		t.Fatalf("select by index: %v", err)
	}
	if byIndex.file.Name != "docs/beta.txt" {
		t.Fatalf("unexpected file %#v", byIndex.file)
	}

	_, err = selectRecoveryFile(payload, "3")
	if err == nil || !strings.Contains(err.Error(), "FILE_NOT_FOUND_IN_MAP") {
		t.Fatalf("expected file not found error, got %v", err)
	}
}

func TestRunFetchLegacyPlaintextFromFileURL(t *testing.T) {
	now := time.Date(2026, 3, 21, 3, 0, 0, 0, time.UTC)
	tempDir := t.TempDir()
	sourceBytes := []byte("legacy encrypted blob bytes")
	if err := os.MkdirAll(filepath.Dir(fixtureFetchLegacySourcePath), 0o755); err != nil {
		t.Fatalf("mkdir source dir: %v", err)
	}
	if err := os.WriteFile(fixtureFetchLegacySourcePath, sourceBytes, 0o600); err != nil {
		t.Fatalf("write source: %v", err)
	}

	privateKey := mustPrivateKey(t, "1111111111111111111111111111111111111111111111111111111111111111")
	doc := loadFixtureDoc(t, "fetch-legacy.qrm")

	challenge, err := buildUnlockChallenge(doc)
	if err != nil {
		t.Fatalf("build challenge: %v", err)
	}
	signature := mustPersonalSign(t, privateKey, challenge)

	qrmPath := copyFixtureQRM(t, tempDir, "fetch-legacy.qrm", "sample-fetch-legacy.qrm")

	outputDir := filepath.Join(tempDir, "out")
	var stdout bytes.Buffer
	err = run([]string{"fetch", qrmPath, "--signer", "manual", "--file", "docs/alpha.bin", "--output-dir", outputDir}, &stdout, ioDiscard{}, strings.NewReader(signature+"\n"), now)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}

	outputPath := filepath.Join(outputDir, "fetch-legacy-map", "docs", "alpha.bin.enc")
	gotBytes, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	if string(gotBytes) != string(sourceBytes) {
		t.Fatalf("unexpected output bytes %q", gotBytes)
	}
	if !strings.Contains(stdout.String(), "Phase 5A complete: encrypted blob fetched") {
		t.Fatalf("unexpected stdout: %s", stdout.String())
	}
}

func TestRunFetchSessionBoundEncryptedFromFileURL(t *testing.T) {
	now := time.Date(2026, 3, 21, 4, 0, 0, 0, time.UTC)
	tempDir := t.TempDir()
	sourceBytes := []byte("session-bound encrypted blob bytes")
	if err := os.MkdirAll(filepath.Dir(fixtureFetchSessionSourcePath), 0o755); err != nil {
		t.Fatalf("mkdir source dir: %v", err)
	}
	if err := os.WriteFile(fixtureFetchSessionSourcePath, sourceBytes, 0o600); err != nil {
		t.Fatalf("write source: %v", err)
	}

	privateKey := mustPrivateKey(t, "1111111111111111111111111111111111111111111111111111111111111111")
	doc := loadFixtureDoc(t, "fetch-session.qrm")
	signature := mustPersonalSign(t, privateKey, doc.Header.PayloadEncryption.SigningChallenge)
	qrmPath := copyFixtureQRM(t, tempDir, "fetch-session.qrm", "sample-fetch-session.qrm")

	outputDir := filepath.Join(tempDir, "out")
	var stdout bytes.Buffer
	err := run([]string{"fetch", qrmPath, "--signer", "manual", "--file", "1", "--output-dir", outputDir}, &stdout, ioDiscard{}, strings.NewReader(signature+"\n"), now)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}

	outputPath := filepath.Join(outputDir, "fetch-session-map", "blob", "session-alpha.enc")
	gotBytes, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	if string(gotBytes) != string(sourceBytes) {
		t.Fatalf("unexpected output bytes %q", gotBytes)
	}
	if !strings.Contains(stdout.String(), "fetch_source=provider_operation_ref:file://") ||
		!strings.Contains(stdout.String(), "fetch_mode=atomic_primitive") ||
		!strings.Contains(stdout.String(), "package_structure=recovery_package_v1") ||
		!strings.Contains(stdout.String(), "fetch_role=atomic_recovery_primitive") {
		t.Fatalf("unexpected stdout: %s", stdout.String())
	}

	metadataPath := outputPath + ".meta.json"
	rawMetadata, err := os.ReadFile(metadataPath)
	if err != nil {
		t.Fatalf("read metadata: %v", err)
	}
	var metadata fetchMetadata
	if err := json.Unmarshal(rawMetadata, &metadata); err != nil {
		t.Fatalf("unmarshal metadata: %v", err)
	}
	if metadata.FileID != opaqueTestFileID(0) {
		t.Fatalf("expected sidecar file_id=%q, got %#v", opaqueTestFileID(0), metadata)
	}
	if metadata.FileID == "piece-fetch-session" {
		t.Fatalf("expected sidecar file_id to stay opaque and not reuse cid, got %#v", metadata)
	}
	uuidV4Pattern := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	if !uuidV4Pattern.MatchString(metadata.FileID) {
		t.Fatalf("expected sidecar file_id to be opaque UUID v4, got %#v", metadata)
	}
}

func TestRunFetchLegacyPerExportEncryptedFromFileURL(t *testing.T) {
	now := time.Date(2026, 3, 21, 4, 30, 0, 0, time.UTC)
	tempDir := t.TempDir()
	sourceBytes := []byte("legacy per-export encrypted blob bytes")
	if err := os.MkdirAll(filepath.Dir(fixtureFetchPerExportSource), 0o755); err != nil {
		t.Fatalf("mkdir source dir: %v", err)
	}
	if err := os.WriteFile(fixtureFetchPerExportSource, sourceBytes, 0o600); err != nil {
		t.Fatalf("write source: %v", err)
	}

	privateKey := mustPrivateKey(t, "1111111111111111111111111111111111111111111111111111111111111111")
	doc := loadFixtureDoc(t, "fetch-per-export.qrm")
	challenge, err := buildUnlockChallenge(doc)
	if err != nil {
		t.Fatalf("build challenge: %v", err)
	}
	signature := mustPersonalSign(t, privateKey, challenge)
	qrmPath := copyFixtureQRM(t, tempDir, "fetch-per-export.qrm", "sample-fetch-per-export.qrm")

	outputDir := filepath.Join(tempDir, "out")
	var stdout bytes.Buffer
	err = run([]string{"fetch", qrmPath, "--signer", "manual", "--file", "blob/per-export-alpha", "--output-dir", outputDir}, &stdout, ioDiscard{}, strings.NewReader(signature+"\n"), now)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}

	outputPath := filepath.Join(outputDir, "fetch-per-export-map", "blob", "per-export-alpha.enc")
	gotBytes, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	if string(gotBytes) != string(sourceBytes) {
		t.Fatalf("unexpected output bytes %q", gotBytes)
	}
	if !strings.Contains(stdout.String(), "payload_unlocked=true") {
		t.Fatalf("unexpected stdout: %s", stdout.String())
	}
}

func TestBuildPieceGatewaySourceFromCID(t *testing.T) {
	file := recoveryMapFileIndex{
		Name: "blob/gateway-alpha",
		CID:  "bafk-test-piece",
	}

	source, ok, err := buildPieceGatewaySource(file, "https://calibration.example")
	if err != nil {
		t.Fatalf("build piece gateway source: %v", err)
	}
	if !ok {
		t.Fatalf("expected piece gateway source")
	}
	if source.location != "https://calibration.example/piece/bafk-test-piece" {
		t.Fatalf("unexpected source %#v", source)
	}
}

func TestRunFetchUnsupportedFetchSource(t *testing.T) {
	now := time.Date(2026, 3, 21, 5, 0, 0, 0, time.UTC)
	privateKey := mustPrivateKey(t, "1111111111111111111111111111111111111111111111111111111111111111")
	vaultOwner := strings.ToLower(crypto.PubkeyToAddress(privateKey.PublicKey).Hex())
	doc := recoveryMapDocument{
		Header: recoveryMapHeader{
			Schema:                recoveryMapSchema,
			MapID:                 "unsupported-fetch-map",
			GeneratedAt:           now.Format(time.RFC3339Nano),
			VaultOwner:            vaultOwner,
			VaultStateHash:        strings.Repeat("3", 64),
			SubscriptionExpiresAt: "2099-01-01T00:00:00Z",
			PayloadEncryption: recoveryPayloadEncryption{
				Algorithm: "AES-256-GCM",
				KDF:       "HKDF-SHA256",
				Nonce:     "bm9uY2U=",
				Binding:   "wallet_bound_personal_sign_v1",
			},
		},
		Payload: &recoveryMapPayload{
			FWSSNetwork:    "phase5a-test",
			FWSSAPIVersion: "v1",
			FileIndex: []recoveryMapFileIndex{
				{
					Name:   "missing-source.bin",
					CID:    "piece-missing",
					Status: "stored",
					StorageRefs: []recoveryMapStorageRef{
						{Kind: "provider_operation_ref", Value: "op_missing"},
					},
				},
			},
		},
	}

	challenge, err := buildUnlockChallenge(doc)
	if err != nil {
		t.Fatalf("build challenge: %v", err)
	}
	signature := mustPersonalSign(t, privateKey, challenge)

	tempDir := t.TempDir()
	qrmPath := filepath.Join(tempDir, "unsupported.qrm")
	raw, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatalf("marshal qrm: %v", err)
	}
	if err := os.WriteFile(qrmPath, append(raw, '\n'), 0o600); err != nil {
		t.Fatalf("write qrm: %v", err)
	}

	oldEnv := os.Getenv(pieceGatewayBaseURLEnv)
	os.Unsetenv(pieceGatewayBaseURLEnv)
	defer func() {
		if oldEnv != "" {
			os.Setenv(pieceGatewayBaseURLEnv, oldEnv)
		}
	}()

	err = run([]string{"fetch", qrmPath, "--signer", "manual", "--file", "missing-source.bin"}, ioDiscard{}, ioDiscard{}, strings.NewReader(signature+"\n"), now)
	if err == nil || !strings.Contains(err.Error(), "UNSUPPORTED_FETCH_SOURCE") {
		t.Fatalf("expected unsupported fetch source error, got %v", err)
	}
}

func TestRunFetchRecoveryPackageV1UnsupportedFetchSourcePrintsSemanticPrelude(t *testing.T) {
	now := time.Date(2026, 3, 24, 6, 0, 0, 0, time.UTC)
	privateKey := mustPrivateKey(t, "1111111111111111111111111111111111111111111111111111111111111111")
	vaultOwner := strings.ToLower(crypto.PubkeyToAddress(privateKey.PublicKey).Hex())
	doc := recoveryMapDocument{
		Header: recoveryMapHeader{
			Schema:                recoveryMapSchema,
			MapID:                 "unsupported-v1-fetch-map",
			GeneratedAt:           now.Format(time.RFC3339Nano),
			VaultOwner:            vaultOwner,
			VaultStateHash:        strings.Repeat("9", 64),
			SubscriptionExpiresAt: "2099-01-01T00:00:00Z",
			PayloadEncryption: recoveryPayloadEncryption{
				Algorithm: "AES-256-GCM",
				KDF:       "HKDF-SHA256",
				Nonce:     "bm9uY2UxMjM0NTY=",
				Binding:   "wallet_bound_personal_sign_v1",
			},
		},
		Payload: &recoveryMapPayload{
			FWSSNetwork:    "phase5a-v1-test",
			FWSSAPIVersion: "v1",
			Snapshot: &recoveryPackageSnapshot{
				SchemaVersion:         recoveryPackageSchemaVersion,
				PackageID:             "unsupported-v1-fetch-map",
				MapID:                 "unsupported-v1-fetch-map",
				VaultOwner:            vaultOwner,
				VaultStateHash:        strings.Repeat("9", 64),
				GeneratedAt:           now.Format(time.RFC3339Nano),
				SubscriptionExpiresAt: "2099-01-01T00:00:00Z",
				FileCount:             1,
				PackageProtectionMode: payloadProtectionLegacyPlaintext,
				RecoveryFlowVersion:   "recover-all.v1",
			},
			FileIndex: []recoveryMapFileIndex{
				{
					FileID:      opaqueTestFileID(0),
					FileName:    "missing-source.bin",
					LogicalPath: "missing-source.bin",
					Name:        "missing-source.bin",
					Size:        123,
					CID:         "piece-missing",
					Status:      "stored",
					StorageRefs: []recoveryMapStorageRef{
						{Kind: "provider_operation_ref", Value: "op_missing"},
					},
					UploadedAt: "2026-03-24T06:00:00Z",
					ExpiresAt:  "2099-01-01T00:00:00Z",
				},
			},
			FetchSources: []recoveryPackageFetchSource{
				{
					FileID:                 opaqueTestFileID(0),
					SourceType:             "provider_operation_ref",
					SourceRef:              "op_missing",
					FetchCapabilityVersion: "qave.recovery-fetch.v1",
				},
			},
			WrappedKeys: []recoveryPackageWrappedKey{
				{
					FileID:             opaqueTestFileID(0),
					KeyWrapVersion:     1,
					KeyMaterialVersion: 1,
				},
			},
			RecoveryPolicy: &recoveryPackageRecoveryPolicy{
				RequiresWalletAuth:     true,
				RequiresRecoveryKey:    true,
				TrustedDeviceSupported: false,
				RecoverAllMode:         "batch_only",
				LocalDecryptRequired:   true,
				LocalPackageRequired:   true,
			},
		},
	}

	challenge, err := buildUnlockChallenge(doc)
	if err != nil {
		t.Fatalf("build challenge: %v", err)
	}
	signature := mustPersonalSign(t, privateKey, challenge)

	tempDir := t.TempDir()
	qrmPath := filepath.Join(tempDir, "unsupported-v1.qrm")
	raw, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatalf("marshal qrm: %v", err)
	}
	if err := os.WriteFile(qrmPath, append(raw, '\n'), 0o600); err != nil {
		t.Fatalf("write qrm: %v", err)
	}

	oldEnv := os.Getenv(pieceGatewayBaseURLEnv)
	os.Unsetenv(pieceGatewayBaseURLEnv)
	defer func() {
		if oldEnv != "" {
			os.Setenv(pieceGatewayBaseURLEnv, oldEnv)
		}
	}()

	var stdout bytes.Buffer
	err = run([]string{"fetch", qrmPath, "--signer", "manual", "--file", "missing-source.bin"}, &stdout, ioDiscard{}, strings.NewReader(signature+"\n"), now)
	if err == nil || !strings.Contains(err.Error(), "UNSUPPORTED_FETCH_SOURCE") {
		t.Fatalf("expected unsupported fetch source error, got %v", err)
	}
	if !strings.Contains(stdout.String(), "package_structure=recovery_package_v1") ||
		!strings.Contains(stdout.String(), "fetch_mode=atomic_primitive") {
		t.Fatalf("expected semantic prelude before fetch failure, got stdout=%s", stdout.String())
	}
}

func TestRunFetchProviderPieceURLStorageRef(t *testing.T) {
	now := time.Date(2026, 3, 21, 4, 0, 0, 0, time.UTC)
	tempDir := t.TempDir()
	privateKey := mustPrivateKey(t, "1111111111111111111111111111111111111111111111111111111111111111")
	sourceBytes := []byte("provider-piece-url blob content")
	doc := loadFixtureDoc(t, "fetch-piece-url.qrm")

	challenge, err := buildUnlockChallenge(doc)
	if err != nil {
		t.Fatalf("build challenge: %v", err)
	}
	signature := mustPersonalSign(t, privateKey, challenge)
	qrmPath := copyFixtureQRM(t, tempDir, "fetch-piece-url.qrm", "fetch-piece-url.qrm")

	originalFetchClient := fetchHTTPClient
	fetchHTTPClient = &http.Client{
		Timeout: defaultFetchHTTPTimeout,
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			if req.URL.String() != "http://fixture.invalid/piece/bafytestpieceurl" {
				t.Fatalf("unexpected provider_piece_url request %q", req.URL.String())
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewReader(sourceBytes)),
				Header:     make(http.Header),
				Request:    req,
			}, nil
		}),
	}
	defer func() {
		fetchHTTPClient = originalFetchClient
	}()

	outputDir := filepath.Join(tempDir, "out")
	var stdout bytes.Buffer
	err = run([]string{"fetch", qrmPath, "--signer", "manual", "--file", "blob/piece-url-alpha", "--output-dir", outputDir}, &stdout, ioDiscard{}, strings.NewReader(signature+"\n"), now)
	if err != nil {
		t.Fatalf("fetch with provider_piece_url failed: %v\nstdout: %s", err, stdout.String())
	}

	outputPath := filepath.Join(outputDir, "fetch-piece-url-map", "blob", "piece-url-alpha.enc")
	gotBytes, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	if string(gotBytes) != string(sourceBytes) {
		t.Fatalf("unexpected output bytes %q", gotBytes)
	}
	if !strings.Contains(stdout.String(), "Phase 5A complete: encrypted blob fetched") {
		t.Fatalf("unexpected stdout: %s", stdout.String())
	}
}

func TestResolveFetchSourceProviderPieceURL(t *testing.T) {
	for _, tc := range []struct {
		name       string
		refs       []recoveryMapStorageRef
		wantURL    string
		wantSource string
	}{
		{
			name:       "provider_piece_url with http",
			refs:       []recoveryMapStorageRef{{Kind: "provider_piece_url", Value: "https://piece-gateway.example.com/piece/bafytest"}},
			wantURL:    "https://piece-gateway.example.com/piece/bafytest",
			wantSource: "provider_piece_url:https://piece-gateway.example.com/piece/bafytest",
		},
		{
			name:       "provider_piece_url first",
			refs:       []recoveryMapStorageRef{{Kind: "provider_piece_url", Value: "https://gateway.io/piece/cid"}, {Kind: "bucket", Value: "default"}},
			wantURL:    "https://gateway.io/piece/cid",
			wantSource: "provider_piece_url:https://gateway.io/piece/cid",
		},
		{
			name:       "provider_piece_url normalizes known typo host",
			refs:       []recoveryMapStorageRef{{Kind: "provider_piece_url", Value: "https://calibration-pdp.infrafolio.com/piece/bafytest"}},
			wantURL:    "https://caliberation-pdp.infrafolio.com/piece/bafytest",
			wantSource: "provider_piece_url:https://caliberation-pdp.infrafolio.com/piece/bafytest",
		},
		{
			name:       "other_refs without provider_piece_url",
			refs:       []recoveryMapStorageRef{{Kind: "bucket", Value: "default"}, {Kind: "provider_operation_ref", Value: "op_test"}},
			wantURL:    "",
			wantSource: "",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			file := recoveryMapFileIndex{
				Name:        "test.txt",
				Size:        100,
				Status:      "stored",
				CID:         "",
				StorageRefs: tc.refs,
			}
			source, ok := firstDirectFetchLocation(file)
			if tc.wantURL == "" {
				if ok {
					t.Fatalf("expected no fetch source for %+v, got %+v", tc.refs, source)
				}
				return
			}
			if !ok {
				t.Fatalf("expected fetch source for %+v, got none", tc.refs)
			}
			if source.location != tc.wantURL {
				t.Fatalf("expected location %q, got %q", tc.wantURL, source.location)
			}
			if source.description != tc.wantSource {
				t.Fatalf("expected description %q, got %q", tc.wantSource, source.description)
			}
		})
	}
}

func TestRunFetchSequentialMultiFileRestoreAll(t *testing.T) {
	now := time.Date(2026, 3, 21, 4, 0, 0, 0, time.UTC)
	tempDir := t.TempDir()
	privateKey := mustPrivateKey(t, "1111111111111111111111111111111111111111111111111111111111111111")

	files := []struct {
		name    string
		content []byte
	}{
		{"docs/readme.txt", []byte("small document content")},
		{"data/report.csv", []byte("medium csv data here with some rows")},
		{"images/photo.png", bytes.Repeat([]byte("image-bytes-"), 100)},
		{"archives/backup.zip", bytes.Repeat([]byte("zip-data-chunk-"), 1000)},
	}
	doc := loadFixtureDoc(t, "fetch-sequential.qrm")
	challenge, err := buildUnlockChallenge(doc)
	if err != nil {
		t.Fatalf("build challenge: %v", err)
	}
	signature := mustPersonalSign(t, privateKey, challenge)
	qrmPath := copyFixtureQRM(t, tempDir, "fetch-sequential.qrm", "sequential-fetch.qrm")

	contentByPath := make(map[string][]byte, len(files))
	for _, f := range files {
		contentByPath["/piece/"+f.name] = f.content
	}
	originalFetchClient := fetchHTTPClient
	fetchHTTPClient = &http.Client{
		Timeout: defaultFetchHTTPTimeout,
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			content, ok := contentByPath[req.URL.EscapedPath()]
			if !ok {
				t.Fatalf("unexpected sequential fetch path %q", req.URL.EscapedPath())
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewReader(content)),
				Header:     make(http.Header),
				Request:    req,
			}, nil
		}),
	}
	defer func() {
		fetchHTTPClient = originalFetchClient
	}()

	for i, f := range files {
		outputDir := filepath.Join(tempDir, fmt.Sprintf("out-%d", i))
		var stdout bytes.Buffer
		err := run([]string{"fetch", qrmPath, "--signer", "manual", "--file", f.name, "--output-dir", outputDir}, &stdout, ioDiscard{}, strings.NewReader(signature+"\n"), now)
		if err != nil {
			t.Fatalf("fetch file %d (%s) failed: %v\nstdout: %s", i+1, f.name, err, stdout.String())
		}
		outputPath := filepath.Join(outputDir, "sequential-fetch-test", f.name+".enc")
		gotBytes, err := os.ReadFile(outputPath)
		if err != nil {
			t.Fatalf("read output for file %d (%s): %v", i+1, f.name, err)
		}
		if string(gotBytes) != string(f.content) {
			t.Fatalf("file %d (%s): expected %d bytes, got %d", i+1, f.name, len(f.content), len(gotBytes))
		}
	}
}
