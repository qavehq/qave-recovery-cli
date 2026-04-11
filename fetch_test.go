package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
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
	sourcePath := filepath.Join(tempDir, "source-alpha.enc")
	sourceBytes := []byte("legacy encrypted blob bytes")
	if err := os.WriteFile(sourcePath, sourceBytes, 0o600); err != nil {
		t.Fatalf("write source: %v", err)
	}

	privateKey := mustPrivateKey(t, "1111111111111111111111111111111111111111111111111111111111111111")
	vaultOwner := strings.ToLower(crypto.PubkeyToAddress(privateKey.PublicKey).Hex())
	doc := recoveryMapDocument{
		Header: recoveryMapHeader{
			Schema:                recoveryMapSchema,
			MapID:                 "fetch-legacy-map",
			GeneratedAt:           now.Format(time.RFC3339Nano),
			VaultOwner:            vaultOwner,
			VaultStateHash:        strings.Repeat("1", 64),
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
					Name:   "docs/alpha.bin",
					Size:   int64(len(sourceBytes)),
					CID:    "piece-fetch-alpha",
					Status: "stored",
					StorageRefs: []recoveryMapStorageRef{
						{Kind: "provider_operation_ref", Value: (&url.URL{Scheme: "file", Path: sourcePath}).String()},
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

	qrmPath := filepath.Join(tempDir, "sample-fetch-legacy.qrm")
	raw, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatalf("marshal qrm: %v", err)
	}
	if err := os.WriteFile(qrmPath, append(raw, '\n'), 0o600); err != nil {
		t.Fatalf("write qrm: %v", err)
	}

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
	sourcePath := filepath.Join(tempDir, "source-session.enc")
	if err := os.WriteFile(sourcePath, sourceBytes, 0o600); err != nil {
		t.Fatalf("write source: %v", err)
	}

	privateKey := mustPrivateKey(t, "1111111111111111111111111111111111111111111111111111111111111111")
	vaultOwner := strings.ToLower(crypto.PubkeyToAddress(privateKey.PublicKey).Hex())
	signingChallenge := strings.Join([]string{
		sessionChallengeVersionLine,
		"wallet=" + vaultOwner,
		"issued_at=" + now.Format(time.RFC3339Nano),
		"nonce=session-fetch-seed",
		"purpose=" + sessionChallengePurpose,
	}, "\n")

	doc := recoveryMapDocument{
		Header: recoveryMapHeader{
			Schema:                recoveryMapSchema,
			MapID:                 "fetch-session-map",
			GeneratedAt:           now.Format(time.RFC3339Nano),
			VaultOwner:            vaultOwner,
			VaultStateHash:        strings.Repeat("2", 64),
			SubscriptionExpiresAt: "2099-01-01T00:00:00Z",
			PayloadEncryption: recoveryPayloadEncryption{
				Algorithm:           "AES-256-GCM",
				KDF:                 "HKDF-SHA256",
				Nonce:               "c2Vzc2l2MDAwMDAx",
				Binding:             "wallet_bound_personal_sign_v1",
				PayloadProtection:   payloadProtectionWalletBoundEncrypted,
				Encoding:            "base64",
				SigningScope:        signingScopeSessionBoundV1,
				SigningScopeVersion: "v1",
				SigningChallenge:    signingChallenge,
			},
		},
	}
	payload := buildRecoveryPackageV1Payload(doc.Header, []recoveryMapFileIndex{
		{
			Name:   "blob/session-alpha",
			Size:   int64(len(sourceBytes)),
			CID:    "piece-fetch-session",
			Status: "stored",
			StorageRefs: []recoveryMapStorageRef{
				{Kind: "provider_operation_ref", Value: (&url.URL{Scheme: "file", Path: sourcePath}).String()},
			},
		},
	})

	signature := mustPersonalSign(t, privateKey, signingChallenge)
	sessionSeed, err := deriveSessionExportSeed(signingChallenge, signature, vaultOwner)
	if err != nil {
		t.Fatalf("derive session seed: %v", err)
	}
	key, err := derivePayloadKeyFromSessionSeed(doc, sessionSeed)
	if err != nil {
		t.Fatalf("derive payload key: %v", err)
	}
	ciphertext, tag, err := encryptPayload(doc, payload, key)
	if err != nil {
		t.Fatalf("encrypt payload: %v", err)
	}
	doc.PayloadCiphertext = ciphertext
	doc.PayloadTag = tag

	qrmPath := filepath.Join(tempDir, "sample-fetch-session.qrm")
	raw, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatalf("marshal qrm: %v", err)
	}
	if err := os.WriteFile(qrmPath, append(raw, '\n'), 0o600); err != nil {
		t.Fatalf("write qrm: %v", err)
	}

	outputDir := filepath.Join(tempDir, "out")
	var stdout bytes.Buffer
	err = run([]string{"fetch", qrmPath, "--signer", "manual", "--file", "1", "--output-dir", outputDir}, &stdout, ioDiscard{}, strings.NewReader(signature+"\n"), now)
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
	sourcePath := filepath.Join(tempDir, "source-per-export.enc")
	if err := os.WriteFile(sourcePath, sourceBytes, 0o600); err != nil {
		t.Fatalf("write source: %v", err)
	}

	privateKey := mustPrivateKey(t, "1111111111111111111111111111111111111111111111111111111111111111")
	vaultOwner := strings.ToLower(crypto.PubkeyToAddress(privateKey.PublicKey).Hex())
	doc := recoveryMapDocument{
		Header: recoveryMapHeader{
			Schema:                recoveryMapSchema,
			MapID:                 "fetch-per-export-map",
			GeneratedAt:           now.Format(time.RFC3339Nano),
			VaultOwner:            vaultOwner,
			VaultStateHash:        strings.Repeat("5", 64),
			SubscriptionExpiresAt: "2099-01-01T00:00:00Z",
			PayloadEncryption: recoveryPayloadEncryption{
				Algorithm:         "AES-256-GCM",
				KDF:               "HKDF-SHA256",
				Nonce:             "cGVyZXhwb3J0MDAx",
				Binding:           "wallet_bound_personal_sign_v1",
				PayloadProtection: payloadProtectionWalletBoundEncrypted,
				Encoding:          "base64",
				SigningScope:      signingScopeLegacyPerExport,
			},
		},
	}
	payload := recoveryMapPayload{
		FWSSNetwork:    "phase5a-per-export-test",
		FWSSAPIVersion: "v1",
		FileIndex: []recoveryMapFileIndex{
			{
				Name:   "blob/per-export-alpha",
				Size:   int64(len(sourceBytes)),
				CID:    "piece-fetch-per-export",
				Status: "stored",
				StorageRefs: []recoveryMapStorageRef{
					{Kind: "provider_operation_ref", Value: (&url.URL{Scheme: "file", Path: sourcePath}).String()},
				},
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

	qrmPath := filepath.Join(tempDir, "sample-fetch-per-export.qrm")
	raw, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatalf("marshal qrm: %v", err)
	}
	if err := os.WriteFile(qrmPath, append(raw, '\n'), 0o600); err != nil {
		t.Fatalf("write qrm: %v", err)
	}

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
	vaultOwner := strings.ToLower(crypto.PubkeyToAddress(privateKey.PublicKey).Hex())

	sourceBytes := []byte("provider-piece-url blob content")
	mux := http.NewServeMux()
	mux.HandleFunc("/piece/bafytestpieceurl", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		w.Write(sourceBytes)
	})
	server := &http.Server{Handler: mux}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go server.Serve(listener)
	defer server.Close()

	gatewayBase := "http://" + listener.Addr().String()

	doc := recoveryMapDocument{
		Header: recoveryMapHeader{
			Schema:                recoveryMapSchema,
			MapID:                 "fetch-piece-url-map",
			GeneratedAt:           now.Format(time.RFC3339Nano),
			VaultOwner:            vaultOwner,
			VaultStateHash:        strings.Repeat("3", 64),
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
	payload := buildRecoveryPackageV1Payload(doc.Header, []recoveryMapFileIndex{
		{
			Name:   "blob/piece-url-alpha",
			Size:   int64(len(sourceBytes)),
			CID:    "bafytestpieceurl",
			Status: "stored",
			StorageRefs: []recoveryMapStorageRef{
				{Kind: "provider_operation_ref", Value: "op_alpha"},
				{Kind: "provider_piece_url", Value: gatewayBase + "/piece/bafytestpieceurl"},
			},
		},
	})

	challenge, err := buildUnlockChallenge(doc)
	if err != nil {
		t.Fatalf("build challenge: %v", err)
	}
	signature := mustPersonalSign(t, privateKey, challenge)
	key, err := deriveUnlockKey(doc, challenge, signature)
	if err != nil {
		t.Fatalf("derive unlock key: %v", err)
	}
	ciphertext, tag, err := encryptPayload(doc, payload, key)
	if err != nil {
		t.Fatalf("encrypt payload: %v", err)
	}
	doc.PayloadCiphertext = ciphertext
	doc.PayloadTag = tag

	qrmPath := filepath.Join(tempDir, "fetch-piece-url.qrm")
	raw, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatalf("marshal qrm: %v", err)
	}
	if err := os.WriteFile(qrmPath, append(raw, '\n'), 0o600); err != nil {
		t.Fatalf("write qrm: %v", err)
	}

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

func TestResolveFetchSourceFromPayloadFetchSources(t *testing.T) {
	t.Run("fetch_sources_with_file_url_takes_priority", func(t *testing.T) {
		file := recoveryMapFileIndex{
			FileID:      "file-001",
			Name:        "test.txt",
			CID:         "",
			StorageRefs: []recoveryMapStorageRef{{Kind: "provider_operation_ref", Value: "op_opaque"}},
		}
		fetchSources := []recoveryPackageFetchSource{
			{
				FileID:                 "file-001",
				SourceType:             "provider_piece_url",
				SourceRef:              "https://gateway.example.com/piece/bafyabc",
				FetchCapabilityVersion: "qave.recovery-fetch.v1",
			},
		}
		source, err := resolveFetchSource(file, "", fetchSources)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if source.location != "https://gateway.example.com/piece/bafyabc" {
			t.Fatalf("expected fetch source from payload.FetchSources, got %+v", source)
		}
		if source.kind != "provider_piece_url" {
			t.Fatalf("expected kind=provider_piece_url, got %q", source.kind)
		}
	})

	t.Run("fetch_sources_file_scheme", func(t *testing.T) {
		file := recoveryMapFileIndex{
			FileID:      "file-002",
			Name:        "local.txt",
			CID:         "",
			StorageRefs: nil,
		}
		fetchSources := []recoveryPackageFetchSource{
			{
				FileID:                 "file-002",
				SourceType:             "local_file",
				SourceRef:              "file:///tmp/test.enc",
				FetchCapabilityVersion: "qave.recovery-fetch.v1",
			},
		}
		source, err := resolveFetchSource(file, "", fetchSources)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if source.location != "file:///tmp/test.enc" {
			t.Fatalf("expected file URL source, got %+v", source)
		}
	})

	t.Run("fetch_sources_piece_ref_with_gateway", func(t *testing.T) {
		pieceCID := "bafypiece123"
		file := recoveryMapFileIndex{
			FileID:      "file-003",
			Name:        "piece.bin",
			CID:         "",
			StorageRefs: nil,
		}
		fetchSources := []recoveryPackageFetchSource{
			{
				FileID:                 "file-003",
				SourceType:             "provider_operation_ref",
				SourceRef:              "op_opaque_ref",
				PieceRef:               &pieceCID,
				FetchCapabilityVersion: "qave.recovery-fetch.v1",
			},
		}
		// PieceRef gateway resolution happens at Priority 3 (after StorageRefs),
		// but since this file has no StorageRefs, it reaches the gateway path.
		source, err := resolveFetchSource(file, "https://pdp.example.com", fetchSources)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if source.kind != "piece_gateway" {
			t.Fatalf("expected piece_gateway kind, got %q", source.kind)
		}
		if !strings.Contains(source.location, "/piece/bafypiece123") {
			t.Fatalf("expected piece CID in gateway URL, got %+v", source)
		}
	})

	t.Run("fetch_sources_cid_with_gateway", func(t *testing.T) {
		cidVal := "bafycid456"
		file := recoveryMapFileIndex{
			FileID: "file-004",
			Name:   "cid.bin",
		}
		fetchSources := []recoveryPackageFetchSource{
			{
				FileID:                 "file-004",
				SourceType:             "provider_operation_ref",
				SourceRef:              "op_opaque",
				CID:                    &cidVal,
				FetchCapabilityVersion: "qave.recovery-fetch.v1",
			},
		}
		// CID gateway resolution happens at Priority 3, and since file has
		// no StorageRefs, it reaches the gateway path.
		source, err := resolveFetchSource(file, "https://pdp.example.com", fetchSources)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if source.kind != "piece_gateway" {
			t.Fatalf("expected piece_gateway kind, got %q", source.kind)
		}
		if !strings.Contains(source.location, "/piece/bafycid456") {
			t.Fatalf("expected CID in gateway URL, got %+v", source)
		}
	})

	t.Run("fallback_to_storage_refs_when_no_fetch_sources_match", func(t *testing.T) {
		file := recoveryMapFileIndex{
			FileID: "file-005",
			Name:   "fallback.txt",
			StorageRefs: []recoveryMapStorageRef{
				{Kind: "provider_piece_url", Value: "https://legacy.example.com/piece/legacy"},
			},
		}
		// FetchSources exist but for a different file_id
		fetchSources := []recoveryPackageFetchSource{
			{
				FileID:                 "file-999",
				SourceType:             "provider_piece_url",
				SourceRef:              "https://other.example.com/piece/other",
				FetchCapabilityVersion: "qave.recovery-fetch.v1",
			},
		}
		source, err := resolveFetchSource(file, "", fetchSources)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if source.location != "https://legacy.example.com/piece/legacy" {
			t.Fatalf("expected legacy storage ref fallback, got %+v", source)
		}
	})

	t.Run("fetch_sources_priority_over_storage_refs", func(t *testing.T) {
		file := recoveryMapFileIndex{
			FileID: "file-006",
			Name:   "priority.txt",
			StorageRefs: []recoveryMapStorageRef{
				{Kind: "provider_piece_url", Value: "https://legacy.example.com/piece/old"},
			},
		}
		fetchSources := []recoveryPackageFetchSource{
			{
				FileID:                 "file-006",
				SourceType:             "provider_piece_url",
				SourceRef:              "https://v1.example.com/piece/new",
				FetchCapabilityVersion: "qave.recovery-fetch.v1",
			},
		}
		source, err := resolveFetchSource(file, "", fetchSources)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if source.location != "https://v1.example.com/piece/new" {
			t.Fatalf("expected v1 FetchSources to take priority, got %+v", source)
		}
	})

	t.Run("unfetchable_fetch_source_falls_back_to_legacy", func(t *testing.T) {
		file := recoveryMapFileIndex{
			FileID: "file-007",
			Name:   "opaque.bin",
			StorageRefs: []recoveryMapStorageRef{
				{Kind: "provider_piece_url", Value: "https://legacy.example.com/piece/ok"},
			},
		}
		// FetchSource matches file_id but has opaque non-URL SourceRef and no PieceRef/CID
		fetchSources := []recoveryPackageFetchSource{
			{
				FileID:                 "file-007",
				SourceType:             "provider_operation_ref",
				SourceRef:              "op_not_a_url",
				FetchCapabilityVersion: "qave.recovery-fetch.v1",
			},
		}
		source, err := resolveFetchSource(file, "", fetchSources)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if source.location != "https://legacy.example.com/piece/ok" {
			t.Fatalf("expected fallback to legacy StorageRefs, got %+v", source)
		}
	})

	t.Run("no_sources_at_all_returns_clear_error", func(t *testing.T) {
		file := recoveryMapFileIndex{
			FileID:      "file-008",
			Name:        "nothing.bin",
			CID:         "",
			StorageRefs: nil,
		}
		_, err := resolveFetchSource(file, "", nil)
		if err == nil {
			t.Fatalf("expected error when no sources available")
		}
		if !strings.Contains(err.Error(), "FWSS_REF_NOT_FOUND") {
			t.Fatalf("expected FWSS_REF_NOT_FOUND, got: %v", err)
		}
	})

	t.Run("nil_fetch_sources_uses_legacy_path", func(t *testing.T) {
		file := recoveryMapFileIndex{
			FileID: "file-009",
			Name:   "legacy.txt",
			StorageRefs: []recoveryMapStorageRef{
				{Kind: "provider_piece_url", Value: "https://legacy.example.com/piece/test"},
			},
		}
		source, err := resolveFetchSource(file, "", nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if source.location != "https://legacy.example.com/piece/test" {
			t.Fatalf("expected legacy path with nil fetchSources, got %+v", source)
		}
	})

	t.Run("storage_refs_direct_url_beats_fetch_sources_gateway", func(t *testing.T) {
		// When FetchSources only has PieceRef (no direct SourceRef URL) but
		// StorageRefs has a direct URL, StorageRefs should win.
		pieceCID := "bafygateway"
		file := recoveryMapFileIndex{
			FileID: "file-010",
			Name:   "mixed.txt",
			StorageRefs: []recoveryMapStorageRef{
				{Kind: "provider_piece_url", Value: "https://direct.example.com/piece/direct"},
			},
		}
		fetchSources := []recoveryPackageFetchSource{
			{
				FileID:                 "file-010",
				SourceType:             "provider_operation_ref",
				SourceRef:              "op_opaque",
				PieceRef:               &pieceCID,
				FetchCapabilityVersion: "qave.recovery-fetch.v1",
			},
		}
		source, err := resolveFetchSource(file, "https://gateway.example.com", fetchSources)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		// StorageRefs direct URL should beat FetchSources gateway
		if source.location != "https://direct.example.com/piece/direct" {
			t.Fatalf("expected StorageRefs direct URL to beat FetchSources gateway, got %+v", source)
		}
	})
}

func TestRunFetchSequentialMultiFileRestoreAll(t *testing.T) {
	now := time.Date(2026, 3, 21, 4, 0, 0, 0, time.UTC)
	tempDir := t.TempDir()
	privateKey := mustPrivateKey(t, "1111111111111111111111111111111111111111111111111111111111111111")
	vaultOwner := strings.ToLower(crypto.PubkeyToAddress(privateKey.PublicKey).Hex())

	files := []struct {
		name    string
		content []byte
	}{
		{"docs/readme.txt", []byte("small document content")},
		{"data/report.csv", []byte("medium csv data here with some rows")},
		{"images/photo.png", bytes.Repeat([]byte("image-bytes-"), 100)},
		{"archives/backup.zip", bytes.Repeat([]byte("zip-data-chunk-"), 1000)},
	}

	mux := http.NewServeMux()
	for _, f := range files {
		content := f.content
		name := f.name
		mux.HandleFunc("/piece/"+url.PathEscape(name), func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/octet-stream")
			w.WriteHeader(http.StatusOK)
			w.Write(content)
		})
	}

	server := &http.Server{Handler: mux}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go server.Serve(listener)
	defer server.Close()

	gatewayBase := "http://" + listener.Addr().String()

	doc := recoveryMapDocument{
		Header: recoveryMapHeader{
			Schema:                recoveryMapSchema,
			MapID:                 "sequential-fetch-test",
			GeneratedAt:           now.Format(time.RFC3339Nano),
			VaultOwner:            vaultOwner,
			VaultStateHash:        strings.Repeat("4", 64),
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

	payloadFiles := make([]recoveryMapFileIndex, len(files))
	for i, f := range files {
		payloadFiles[i] = recoveryMapFileIndex{
			Name:   f.name,
			Size:   int64(len(f.content)),
			CID:    f.name,
			Status: "stored",
			StorageRefs: []recoveryMapStorageRef{
				{Kind: "provider_piece_url", Value: gatewayBase + "/piece/" + url.PathEscape(f.name)},
			},
		}
	}
	payload := buildRecoveryPackageV1Payload(doc.Header, payloadFiles)

	challenge, err := buildUnlockChallenge(doc)
	if err != nil {
		t.Fatalf("build challenge: %v", err)
	}
	signature := mustPersonalSign(t, privateKey, challenge)
	key, err := deriveUnlockKey(doc, challenge, signature)
	if err != nil {
		t.Fatalf("derive unlock key: %v", err)
	}
	ciphertext, tag, err := encryptPayload(doc, payload, key)
	if err != nil {
		t.Fatalf("encrypt payload: %v", err)
	}
	doc.PayloadCiphertext = ciphertext
	doc.PayloadTag = tag

	qrmPath := filepath.Join(tempDir, "sequential-fetch.qrm")
	raw, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatalf("marshal qrm: %v", err)
	}
	if err := os.WriteFile(qrmPath, append(raw, '\n'), 0o600); err != nil {
		t.Fatalf("write qrm: %v", err)
	}

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
