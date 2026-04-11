package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
)

func TestRunDecryptFilePlaintextPayloadWithoutSigner(t *testing.T) {
	now := time.Date(2026, 3, 24, 12, 0, 0, 0, time.UTC)
	tempDir := t.TempDir()

	doc, fileID, _, plaintext, ciphertextBytes := buildPhase3CTestDocument(t, now, false)
	qrmPath := writeQRMFixture(t, tempDir, "phase3c-plaintext.qrm", doc)
	ciphertextPath := writeBytesFixture(t, tempDir, "ciphertext.bin", ciphertextBytes)
	outputPath := filepath.Join(tempDir, "restored.txt")

	var stdout bytes.Buffer
	err := run(
		[]string{"decrypt-file", "--qrm", qrmPath, "--file-id", fileID, "--ciphertext", ciphertextPath, "--output", outputPath},
		&stdout,
		ioDiscard{},
		strings.NewReader("abcde fghjk mnpqr st234\n"),
		now,
	)
	if err != nil {
		t.Fatalf("decrypt-file plaintext: %v", err)
	}

	gotBytes, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	if string(gotBytes) != string(plaintext) {
		t.Fatalf("unexpected plaintext output %q", gotBytes)
	}
	if !strings.Contains(stdout.String(), "payload_unlocked=false") || !strings.Contains(stdout.String(), "decrypt_complete=true") {
		t.Fatalf("unexpected stdout: %s", stdout.String())
	}
}

func TestRunDecryptFileEncryptedPayloadWithManualSigner(t *testing.T) {
	now := time.Date(2026, 3, 24, 13, 0, 0, 0, time.UTC)
	tempDir := t.TempDir()

	doc, fileID, recoveryKey, plaintext, ciphertextBytes := buildPhase3CTestDocument(t, now, true)
	qrmPath := writeQRMFixture(t, tempDir, "phase3c-encrypted.qrm", doc)
	ciphertextPath := writeBytesFixture(t, tempDir, "ciphertext.enc", ciphertextBytes)
	outputPath := filepath.Join(tempDir, "restored.txt")

	challenge, err := buildUnlockChallenge(doc)
	if err != nil {
		t.Fatalf("build unlock challenge: %v", err)
	}
	privateKey := mustPrivateKey(t, "1111111111111111111111111111111111111111111111111111111111111111")
	signature := mustPersonalSign(t, privateKey, challenge)

	var stdout bytes.Buffer
	err = run(
		[]string{"decrypt-file", "--qrm", qrmPath, "--signer", "manual", "--file-id", fileID, "--ciphertext", ciphertextPath, "--output", outputPath},
		&stdout,
		ioDiscard{},
		strings.NewReader(signature+"\n"+recoveryKey+"\n"),
		now,
	)
	if err != nil {
		t.Fatalf("decrypt-file encrypted: %v", err)
	}

	gotBytes, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	if string(gotBytes) != string(plaintext) {
		t.Fatalf("unexpected plaintext output %q", gotBytes)
	}
	if !strings.Contains(stdout.String(), "payload_unlocked=true") || !strings.Contains(stdout.String(), "wallet_address=") {
		t.Fatalf("unexpected stdout: %s", stdout.String())
	}
}

func TestRunDecryptFileEncryptedPayloadRequiresSigner(t *testing.T) {
	now := time.Date(2026, 3, 24, 14, 0, 0, 0, time.UTC)
	tempDir := t.TempDir()

	doc, fileID, _, _, ciphertextBytes := buildPhase3CTestDocument(t, now, true)
	qrmPath := writeQRMFixture(t, tempDir, "phase3c-encrypted.qrm", doc)
	ciphertextPath := writeBytesFixture(t, tempDir, "ciphertext.enc", ciphertextBytes)
	outputPath := filepath.Join(tempDir, "restored.txt")

	err := run(
		[]string{"decrypt-file", "--qrm", qrmPath, "--file-id", fileID, "--ciphertext", ciphertextPath, "--output", outputPath},
		ioDiscard{},
		ioDiscard{},
		strings.NewReader(""),
		now,
	)
	if err == nil || !strings.Contains(err.Error(), "UNLOCK_REQUIRED") {
		t.Fatalf("expected unlock required error, got %v", err)
	}
}

func TestRunDecryptFileFailsClosedWhenFileIDMissing(t *testing.T) {
	now := time.Date(2026, 3, 24, 15, 0, 0, 0, time.UTC)
	tempDir := t.TempDir()

	doc, _, recoveryKey, _, ciphertextBytes := buildPhase3CTestDocument(t, now, false)
	qrmPath := writeQRMFixture(t, tempDir, "phase3c-plaintext.qrm", doc)
	ciphertextPath := writeBytesFixture(t, tempDir, "ciphertext.bin", ciphertextBytes)
	outputPath := filepath.Join(tempDir, "restored.txt")

	err := run(
		[]string{"decrypt-file", "--qrm", qrmPath, "--file-id", "00000000-0000-4000-8000-000000009999", "--ciphertext", ciphertextPath, "--output", outputPath},
		ioDiscard{},
		ioDiscard{},
		strings.NewReader(recoveryKey+"\n"),
		now,
	)
	if err == nil || !strings.Contains(err.Error(), "FILE_ID_NOT_FOUND") {
		t.Fatalf("expected file_id not found error, got %v", err)
	}
}

func TestParseRecoveryKeyMaterialCLIAcceptsSupportedFormats(t *testing.T) {
	for _, input := range []string{
		"ABCDE-FGHJK-MNPQR-ST234",
		"abcde fghjk mnpqr st234",
		"abcdefghjkmnpqrst234",
	} {
		normalized, err := parseRecoveryKeyMaterialCLI(input)
		if err != nil {
			t.Fatalf("parse recovery key %q: %v", input, err)
		}
		if normalized != "ABCDEFGHJKMNPQRST234" {
			t.Fatalf("unexpected normalized recovery key %q", normalized)
		}
	}
}

func TestParseRecoveryKeyMaterialCLIRejectsInvalidFormatAndLength(t *testing.T) {
	if _, err := parseRecoveryKeyMaterialCLI("ABCDE-FGHJK-MNPQR-ST23!"); err == nil || !strings.Contains(err.Error(), "RECOVERY_KEY_INVALID_FORMAT") {
		t.Fatalf("expected invalid format error, got %v", err)
	}
	if _, err := parseRecoveryKeyMaterialCLI("ABCDE-FGHJK-MNPQR-ST23"); err == nil || !strings.Contains(err.Error(), "RECOVERY_KEY_INVALID_LENGTH") {
		t.Fatalf("expected invalid length error, got %v", err)
	}
}

func buildPhase3CTestDocument(t *testing.T, now time.Time, encryptedPayload bool) (recoveryMapDocument, string, string, []byte, []byte) {
	t.Helper()

	fileID := "00000000-0000-4000-8000-000000000123"
	recoveryKey := "ABCDEFGHJKMNPQRST234"
	plaintext := []byte("phase3c plaintext data")
	fileKeyBytes := bytes.Repeat([]byte{0x21}, fileKeyLengthBytes)
	contentIV := bytes.Repeat([]byte{0x34}, wrapIVLengthBytes)
	wrapIV := bytes.Repeat([]byte{0x56}, wrapIVLengthBytes)
	saltBytes := bytes.Repeat([]byte{0x78}, 16)

	ciphertextBytes := mustSealAESGCM(t, fileKeyBytes, contentIV, plaintext)
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
	wrappedFileKey := mustSealAESGCM(t, wrapKeyBytes, wrapIV, fileKeyBytes)

	materialVersion := 7
	keyWrapAlgorithm := recoveryWrapAlgorithmAES256GCM
	wrappedFileKeyB64 := base64.StdEncoding.EncodeToString(wrappedFileKey)
	wrapIVB64 := base64.StdEncoding.EncodeToString(wrapIV)

	payload := recoveryMapPayload{
		Snapshot: &recoveryPackageSnapshot{
			SchemaVersion:         recoveryPackageSchemaVersion,
			PackageID:             "phase3c-package",
			MapID:                 "phase3c-package",
			VaultOwner:            "0x123400000000000000000000000000000000abcd",
			VaultStateHash:        strings.Repeat("a", 64),
			GeneratedAt:           now.Format(time.RFC3339Nano),
			SubscriptionExpiresAt: "2099-01-01T00:00:00Z",
			FileCount:             1,
			PackageProtectionMode: payloadProtectionWalletBoundEncrypted,
			RecoveryFlowVersion:   "recover-all.v1",
			RecoveryKDFProfiles: []recoveryPackageKDFProfile{
				{
					MaterialVersion: materialVersion,
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
		FileIndex: []recoveryMapFileIndex{
			{
				FileID:      fileID,
				FileName:    "report.txt",
				LogicalPath: "docs/report.txt",
				Name:        "docs/report.txt",
				Size:        int64(len(plaintext)),
				CID:         "",
				StorageRefs: []recoveryMapStorageRef{
					{Kind: "bucket", Value: "docs"},
				},
				UploadedAt:    now.Format(time.RFC3339Nano),
				SnapshotIndex: 0,
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
					ContentEncryptionIV:        base64.StdEncoding.EncodeToString(contentIV),
				},
				RecoveryMaterialVersion: &materialVersion,
			},
		},
		WrappedKeys: []recoveryPackageWrappedKey{
			{
				FileID:                  fileID,
				RecoveryMaterialVersion: &materialVersion,
				WrappedFileKey:          &wrappedFileKeyB64,
				KeyWrapAlgorithm:        &keyWrapAlgorithm,
				KeyWrapVersion:          recoveryWrapVersion1,
				IV:                      &wrapIVB64,
				KeyMaterialVersion:      recoveryKeyMaterialVersion1,
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
		FWSSNetwork:    "phase2-reserved",
		FWSSAPIVersion: "v1",
	}

	if !encryptedPayload {
		return recoveryMapDocument{
			Header: recoveryMapHeader{
				Schema:                recoveryMapSchema,
				MapID:                 "phase3c-plaintext-map",
				GeneratedAt:           now.Format(time.RFC3339Nano),
				VaultOwner:            "0x123400000000000000000000000000000000abcd",
				VaultStateHash:        strings.Repeat("b", 64),
				SubscriptionExpiresAt: "2099-01-01T00:00:00Z",
				PayloadEncryption: recoveryPayloadEncryption{
					Algorithm: "AES-256-GCM",
					KDF:       "HKDF-SHA256",
					Nonce:     "bm9uY2U=",
					Binding:   "wallet_bound_personal_sign_v1",
				},
			},
			Payload: &payload,
		}, fileID, recoveryKey, plaintext, ciphertextBytes
	}

	privateKey := mustPrivateKey(t, "1111111111111111111111111111111111111111111111111111111111111111")
	vaultOwner := strings.ToLower(crypto.PubkeyToAddress(privateKey.PublicKey).Hex())
	doc := recoveryMapDocument{
		Header: recoveryMapHeader{
			Schema:                recoveryMapSchema,
			MapID:                 "phase3c-encrypted-map",
			GeneratedAt:           now.Format(time.RFC3339Nano),
			VaultOwner:            vaultOwner,
			VaultStateHash:        strings.Repeat("c", 64),
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
	challenge, err := buildChallengeFromDocument(doc)
	if err != nil {
		t.Fatalf("build challenge: %v", err)
	}
	signature := mustPersonalSign(t, privateKey, challenge)
	payloadKey, err := deriveUnlockKey(doc, challenge, signature)
	if err != nil {
		t.Fatalf("derive payload key: %v", err)
	}
	ciphertext, tag, err := encryptPayload(doc, payload, payloadKey)
	if err != nil {
		t.Fatalf("encrypt payload: %v", err)
	}
	doc.PayloadCiphertext = ciphertext
	doc.PayloadTag = tag
	return doc, fileID, recoveryKey, plaintext, ciphertextBytes
}

func mustSealAESGCM(t *testing.T, key []byte, iv []byte, plaintext []byte) []byte {
	t.Helper()
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("aes new cipher: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("cipher new gcm: %v", err)
	}
	return gcm.Seal(nil, iv, plaintext, nil)
}

func writeQRMFixture(t *testing.T, dir string, name string, doc recoveryMapDocument) string {
	t.Helper()
	raw, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatalf("marshal qrm fixture: %v", err)
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, append(raw, '\n'), 0o600); err != nil {
		t.Fatalf("write qrm fixture: %v", err)
	}
	return path
}

func writeBytesFixture(t *testing.T, dir string, name string, content []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("write bytes fixture: %v", err)
	}
	return path
}
