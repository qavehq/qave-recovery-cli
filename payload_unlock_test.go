package main

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
)

func TestRunVerifyAndUnlockEncryptedPayloadLegacyPerExport(t *testing.T) {
	now := time.Date(2026, 3, 21, 0, 0, 0, 0, time.UTC)
	doc, signature := buildEncryptedPhase4Sample(t, now)

	tempDir := t.TempDir()
	path := filepath.Join(tempDir, "sample-phase4.qrm")
	raw, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatalf("marshal sample: %v", err)
	}
	if err := os.WriteFile(path, append(raw, '\n'), 0o600); err != nil {
		t.Fatalf("write sample: %v", err)
	}

	var verifyOut bytes.Buffer
	if err := run([]string{"verify", path}, &verifyOut, ioDiscard{}, strings.NewReader(""), now); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !strings.Contains(verifyOut.String(), "payload_protection=wallet_bound_encrypted") ||
		!strings.Contains(verifyOut.String(), "signing_scope=legacy_per_export") ||
		!strings.Contains(verifyOut.String(), "file_count=locked") ||
		!strings.Contains(verifyOut.String(), "package_structure=locked_payload_unverified") {
		t.Fatalf("unexpected verify output: %s", verifyOut.String())
	}

	var unlockOut bytes.Buffer
	err = run([]string{"unlock", path, "--signer", "manual"}, &unlockOut, ioDiscard{}, strings.NewReader(signature+"\n"), now)
	if err != nil {
		t.Fatalf("unlock: %v", err)
	}
	if !strings.Contains(unlockOut.String(), "payload_unlocked=true") ||
		!strings.Contains(unlockOut.String(), "file_count=2") ||
		!strings.Contains(unlockOut.String(), "package_structure=recovery_package_v1") ||
		!strings.Contains(unlockOut.String(), "recovery_policy_requires_recovery_key=true") ||
		!strings.Contains(unlockOut.String(), "recover_all_mode=batch_only") ||
		!strings.Contains(unlockOut.String(), "recover_all_ready=true") {
		t.Fatalf("unexpected unlock output: %s", unlockOut.String())
	}

	var listOut bytes.Buffer
	err = run([]string{"list", path}, &listOut, ioDiscard{}, strings.NewReader(""), now)
	if err == nil || !strings.Contains(err.Error(), payloadLockedCode) {
		t.Fatalf("expected payload locked error, got %v output=%s", err, listOut.String())
	}
}

func TestRunVerifyAndUnlockEncryptedPayloadSessionBoundV1(t *testing.T) {
	now := time.Date(2026, 3, 21, 0, 0, 0, 0, time.UTC)
	doc, signature := buildEncryptedSessionBoundSample(t, now, "session-a")

	tempDir := t.TempDir()
	path := filepath.Join(tempDir, "sample-phase45-session-bound.qrm")
	raw, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatalf("marshal sample: %v", err)
	}
	if err := os.WriteFile(path, append(raw, '\n'), 0o600); err != nil {
		t.Fatalf("write sample: %v", err)
	}

	var verifyOut bytes.Buffer
	if err := run([]string{"verify", path}, &verifyOut, ioDiscard{}, strings.NewReader(""), now); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !strings.Contains(verifyOut.String(), "payload_protection=wallet_bound_encrypted") ||
		!strings.Contains(verifyOut.String(), "signing_scope=session_bound_v1") ||
		!strings.Contains(verifyOut.String(), "file_count=locked") ||
		!strings.Contains(verifyOut.String(), "package_structure=locked_payload_unverified") {
		t.Fatalf("unexpected verify output: %s", verifyOut.String())
	}

	var unlockOut bytes.Buffer
	err = run([]string{"unlock", path, "--signer", "manual"}, &unlockOut, ioDiscard{}, strings.NewReader(signature+"\n"), now)
	if err != nil {
		t.Fatalf("unlock: %v", err)
	}
	if !strings.Contains(unlockOut.String(), "payload_unlocked=true") || !strings.Contains(unlockOut.String(), "file_count=2") {
		t.Fatalf("unexpected unlock output: %s", unlockOut.String())
	}

	var listOut bytes.Buffer
	err = run([]string{"list", path}, &listOut, ioDiscard{}, strings.NewReader(""), now)
	if err == nil || !strings.Contains(err.Error(), payloadLockedCode) {
		t.Fatalf("expected payload locked error, got %v output=%s", err, listOut.String())
	}
}

func TestRunVerifyRecoveryPackageV1Plaintext(t *testing.T) {
	now := time.Date(2026, 3, 24, 0, 0, 0, 0, time.UTC)
	doc := buildPlaintextRecoveryPackageV1Sample(now)

	tempDir := t.TempDir()
	path := filepath.Join(tempDir, "sample-recovery-package-v1.qrm")
	raw, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatalf("marshal sample: %v", err)
	}
	if err := os.WriteFile(path, append(raw, '\n'), 0o600); err != nil {
		t.Fatalf("write sample: %v", err)
	}

	var verifyOut bytes.Buffer
	if err := run([]string{"verify", path}, &verifyOut, ioDiscard{}, strings.NewReader(""), now); err != nil {
		t.Fatalf("verify: %v", err)
	}

	output := verifyOut.String()
	if !strings.Contains(output, "package_structure=recovery_package_v1") ||
		!strings.Contains(output, "snapshot_file_count=2") ||
		!strings.Contains(output, "fetch_sources_count=2") ||
		!strings.Contains(output, "wrapped_keys_count=2") ||
		!strings.Contains(output, "wrapped_keys_present=true") ||
		!strings.Contains(output, "recovery_policy_requires_wallet_auth=true") ||
		!strings.Contains(output, "recovery_policy_requires_recovery_key=true") ||
		!strings.Contains(output, "recovery_policy_recover_all_mode=batch_only") ||
		!strings.Contains(output, "local_decrypt_required=true") ||
		!strings.Contains(output, "local_package_required=true") ||
		!strings.Contains(output, "recover_all_ready=false") {
		t.Fatalf("unexpected recovery package verify output: %s", output)
	}
}

func TestRunVerifyLegacyRecoveryMapStillWorks(t *testing.T) {
	now := time.Date(2026, 3, 24, 0, 0, 0, 0, time.UTC)
	doc := buildLegacyPlaintextRecoveryMapSample(now)

	tempDir := t.TempDir()
	path := filepath.Join(tempDir, "sample-legacy-recovery-map.qrm")
	raw, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatalf("marshal sample: %v", err)
	}
	if err := os.WriteFile(path, append(raw, '\n'), 0o600); err != nil {
		t.Fatalf("write sample: %v", err)
	}

	var verifyOut bytes.Buffer
	if err := run([]string{"verify", path}, &verifyOut, ioDiscard{}, strings.NewReader(""), now); err != nil {
		t.Fatalf("verify: %v", err)
	}

	output := verifyOut.String()
	if !strings.Contains(output, "package_structure=legacy_recovery_map") ||
		!strings.Contains(output, "payload_protection=legacy_plaintext") ||
		!strings.Contains(output, "file_count=1") {
		t.Fatalf("unexpected legacy verify output: %s", output)
	}
}

type ioDiscard struct{}

func (ioDiscard) Write(p []byte) (int, error) { return len(p), nil }

func buildEncryptedPhase4Sample(t *testing.T, now time.Time) (recoveryMapDocument, string) {
	t.Helper()

	privateKey := mustPrivateKey(t, "1111111111111111111111111111111111111111111111111111111111111111")
	vaultOwner := strings.ToLower(crypto.PubkeyToAddress(privateKey.PublicKey).Hex())
	doc := recoveryMapDocument{
		Header: recoveryMapHeader{
			Schema:                recoveryMapSchema,
			MapID:                 "44444444-5555-6666-7777-888888888888",
			GeneratedAt:           now.Format(time.RFC3339Nano),
			VaultOwner:            vaultOwner,
			VaultStateHash:        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
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
			Name:   "alpha.txt",
			Size:   123,
			CID:    "piece_alpha",
			Status: "stored",
			StorageRefs: []recoveryMapStorageRef{
				{Kind: "bucket", Value: "default"},
			},
			UploadedAt: "2026-03-21T00:00:00Z",
			ExpiresAt:  "2099-01-01T00:00:00Z",
			Encryption: recoveryMapFileEncryption{
				Mode:                "phase4-wallet-bound",
				KeyMaterialIncluded: false,
				KeyDerivation:       "phase2-wallet-bound-hkdf-reserved",
				WalletBinding:       "personal_sign_required",
			},
		},
		{
			Name:   "docs/beta.txt",
			Size:   456,
			CID:    "",
			Status: "replicating",
			StorageRefs: []recoveryMapStorageRef{
				{Kind: "provider_operation_ref", Value: "op_beta"},
			},
			UploadedAt: "2026-03-21T00:10:00Z",
			ExpiresAt:  "2099-01-01T00:00:00Z",
			Encryption: recoveryMapFileEncryption{
				Mode:                "phase4-wallet-bound",
				KeyMaterialIncluded: false,
				KeyDerivation:       "phase2-wallet-bound-hkdf-reserved",
				WalletBinding:       "personal_sign_required",
			},
		},
	})

	challenge, err := buildChallengeFromDocument(doc)
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
	return doc, signature
}

func buildEncryptedSessionBoundSample(t *testing.T, now time.Time, nonceSuffix string) (recoveryMapDocument, string) {
	t.Helper()

	privateKey := mustPrivateKey(t, "1111111111111111111111111111111111111111111111111111111111111111")
	vaultOwner := strings.ToLower(crypto.PubkeyToAddress(privateKey.PublicKey).Hex())
	signingChallenge := strings.Join([]string{
		sessionChallengeVersionLine,
		"wallet=" + vaultOwner,
		"issued_at=" + now.Format(time.RFC3339Nano),
		"nonce=" + nonceSuffix,
		"purpose=" + sessionChallengePurpose,
	}, "\n")

	doc := recoveryMapDocument{
		Header: recoveryMapHeader{
			Schema:                recoveryMapSchema,
			MapID:                 "99999999-aaaa-bbbb-cccc-dddddddddddd",
			GeneratedAt:           now.Format(time.RFC3339Nano),
			VaultOwner:            vaultOwner,
			VaultStateHash:        "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
			SubscriptionExpiresAt: "2099-01-01T00:00:00Z",
			PayloadEncryption: recoveryPayloadEncryption{
				Algorithm:           "AES-256-GCM",
				KDF:                 "HKDF-SHA256",
				Nonce:               "QUJDREVGR0hJSktM",
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
			Name:   "gamma.txt",
			Size:   321,
			CID:    "piece_gamma",
			Status: "stored",
			StorageRefs: []recoveryMapStorageRef{
				{Kind: "bucket", Value: "default"},
			},
			UploadedAt: "2026-03-21T01:00:00Z",
			ExpiresAt:  "2099-01-01T00:00:00Z",
			Encryption: recoveryMapFileEncryption{
				Mode:                "phase45-wallet-bound-session",
				KeyMaterialIncluded: false,
				KeyDerivation:       "session-bound-v1",
				WalletBinding:       "personal_sign_session_required",
			},
		},
		{
			Name:   "docs/delta.txt",
			Size:   654,
			CID:    "",
			Status: "replicating",
			StorageRefs: []recoveryMapStorageRef{
				{Kind: "provider_operation_ref", Value: "op_delta"},
			},
			UploadedAt: "2026-03-21T01:10:00Z",
			ExpiresAt:  "2099-01-01T00:00:00Z",
			Encryption: recoveryMapFileEncryption{
				Mode:                "phase45-wallet-bound-session",
				KeyMaterialIncluded: false,
				KeyDerivation:       "session-bound-v1",
				WalletBinding:       "personal_sign_session_required",
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
	return doc, signature
}

func mustPrivateKey(t *testing.T, hexKey string) *ecdsa.PrivateKey {
	t.Helper()
	key, err := crypto.HexToECDSA(hexKey)
	if err != nil {
		t.Fatalf("hex to ecdsa: %v", err)
	}
	return key
}

func mustPersonalSign(t *testing.T, privateKey *ecdsa.PrivateKey, challenge string) string {
	t.Helper()
	msg := []byte(challenge)
	prefix := fmt.Sprintf("\x19Ethereum Signed Message:\n%d", len(msg))
	digest := crypto.Keccak256([]byte(prefix), msg)
	signature, err := crypto.Sign(digest, privateKey)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	signature[64] += 27
	return "0x" + hex.EncodeToString(signature)
}

func buildPlaintextRecoveryPackageV1Sample(now time.Time) recoveryMapDocument {
	header := recoveryMapHeader{
		Schema:                recoveryMapSchema,
		MapID:                 "pkg-verify-map",
		GeneratedAt:           now.Format(time.RFC3339Nano),
		VaultOwner:            "0x123400000000000000000000000000000000abcd",
		VaultStateHash:        strings.Repeat("7", 64),
		SubscriptionExpiresAt: "2099-01-01T00:00:00Z",
		PayloadEncryption: recoveryPayloadEncryption{
			Algorithm: "AES-256-GCM",
			KDF:       "HKDF-SHA256",
			Nonce:     "bm9uY2U=",
			Binding:   "wallet_bound_personal_sign_v1",
		},
	}
	payload := buildRecoveryPackageV1Payload(header, []recoveryMapFileIndex{
		{
			Name:        "alpha.txt",
			FileID:      opaqueTestFileID(0),
			FileName:    "alpha.txt",
			LogicalPath: "alpha.txt",
			Size:        123,
			CID:         "cid-alpha",
			Status:      "stored",
			StorageRefs: []recoveryMapStorageRef{
				{Kind: "provider_operation_ref", Value: "op-alpha"},
			},
			UploadedAt: "2026-03-24T00:00:00Z",
			ExpiresAt:  "2099-01-01T00:00:00Z",
		},
		{
			Name:        "docs/beta.txt",
			FileID:      opaqueTestFileID(1),
			FileName:    "beta.txt",
			LogicalPath: "docs/beta.txt",
			Size:        456,
			CID:         "",
			Status:      "replicating",
			StorageRefs: []recoveryMapStorageRef{
				{Kind: "provider_operation_ref", Value: "op-beta"},
				{Kind: "provider_dataset_id", Value: "dataset-beta"},
			},
			UploadedAt: "2026-03-24T00:10:00Z",
			ExpiresAt:  "2099-01-01T00:00:00Z",
		},
	})
	return recoveryMapDocument{
		Header:  header,
		Payload: &payload,
	}
}

func buildLegacyPlaintextRecoveryMapSample(now time.Time) recoveryMapDocument {
	return recoveryMapDocument{
		Header: recoveryMapHeader{
			Schema:                recoveryMapSchema,
			MapID:                 "legacy-verify-map",
			GeneratedAt:           now.Format(time.RFC3339Nano),
			VaultOwner:            "0x123400000000000000000000000000000000abcd",
			VaultStateHash:        strings.Repeat("8", 64),
			SubscriptionExpiresAt: "2099-01-01T00:00:00Z",
			PayloadEncryption: recoveryPayloadEncryption{
				Algorithm:         "AES-256-GCM",
				KDF:               "HKDF-SHA256",
				Nonce:             "bm9uY2U=",
				Binding:           "wallet_bound_personal_sign_v1",
				PayloadProtection: payloadProtectionLegacyPlaintext,
				Encoding:          "base64",
				SigningScope:      signingScopeLegacyPerExport,
			},
		},
		Payload: &recoveryMapPayload{
			FWSSNetwork:    "phase1-legacy",
			FWSSAPIVersion: "v1",
			FileIndex: []recoveryMapFileIndex{
				{
					Name:       "legacy-alpha.txt",
					Size:       11,
					CID:        "legacy-cid",
					Status:     "stored",
					UploadedAt: "2026-03-24T00:00:00Z",
					ExpiresAt:  "2099-01-01T00:00:00Z",
				},
			},
		},
	}
}

func buildRecoveryPackageV1Payload(header recoveryMapHeader, files []recoveryMapFileIndex) recoveryMapPayload {
	payloadFiles := make([]recoveryMapFileIndex, 0, len(files))
	fetchSources := make([]recoveryPackageFetchSource, 0, len(files))
	wrappedKeys := make([]recoveryPackageWrappedKey, 0, len(files))

	for index, file := range files {
		if file.FileID == "" {
			file.FileID = opaqueTestFileID(index)
		}
		if file.FileName == "" {
			file.FileName = filepath.Base(file.Name)
		}
		if file.LogicalPath == "" {
			file.LogicalPath = file.Name
		}
		file.SnapshotIndex = index
		payloadFiles = append(payloadFiles, file)

		sourceRef := file.CID
		sourceType := "cid"
		if len(file.StorageRefs) > 0 {
			sourceType = file.StorageRefs[0].Kind
			sourceRef = file.StorageRefs[0].Value
		}
		fetchSource := recoveryPackageFetchSource{
			FileID:                 file.FileID,
			SourceType:             sourceType,
			SourceRef:              sourceRef,
			FetchCapabilityVersion: "qave.recovery-fetch.v1",
		}
		if strings.TrimSpace(file.CID) != "" {
			fetchSource.CID = stringPtr(file.CID)
			fetchSource.PieceRef = stringPtr(file.CID)
		}
		fetchSources = append(fetchSources, fetchSource)

		wrappedKeys = append(wrappedKeys, recoveryPackageWrappedKey{
			FileID:             file.FileID,
			KeyWrapVersion:     1,
			KeyMaterialVersion: 1,
		})
	}

	return recoveryMapPayload{
		Snapshot: &recoveryPackageSnapshot{
			SchemaVersion:         recoveryPackageSchemaVersion,
			PackageID:             header.MapID,
			MapID:                 header.MapID,
			VaultOwner:            header.VaultOwner,
			VaultStateHash:        header.VaultStateHash,
			GeneratedAt:           header.GeneratedAt,
			SubscriptionExpiresAt: header.SubscriptionExpiresAt,
			FileCount:             len(payloadFiles),
			PackageProtectionMode: payloadProtectionOf(recoveryMapDocument{Header: header}),
			RecoveryFlowVersion:   "recover-all.v1",
		},
		FileIndex:    payloadFiles,
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
}

func stringPtr(value string) *string {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	cloned := value
	return &cloned
}

func opaqueTestFileID(index int) string {
	return fmt.Sprintf("00000000-0000-4000-8000-%012d", index+1)
}
