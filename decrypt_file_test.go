package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	decryptFixtureFileID    = "00000000-0000-4000-8000-000000000123"
	decryptFixtureKey       = "ABCDEFGHJKMNPQRST234"
	decryptFixturePlaintext = "phase3c plaintext data"
)

func TestRunDecryptFilePlaintextPayloadWithoutSigner(t *testing.T) {
	now := time.Date(2026, 3, 24, 12, 0, 0, 0, time.UTC)
	tempDir := t.TempDir()

	qrmPath := copyFixtureQRM(t, tempDir, "decrypt-file-plaintext.qrm", "phase3c-plaintext.qrm")
	ciphertextPath := copyFixtureFile(t, "decrypt-file-ciphertext.bin", filepath.Join(tempDir, "ciphertext.bin"))
	outputPath := filepath.Join(tempDir, "restored.txt")

	var stdout bytes.Buffer
	err := run(
		[]string{"decrypt-file", "--qrm", qrmPath, "--file-id", decryptFixtureFileID, "--ciphertext", ciphertextPath, "--output", outputPath},
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
	if string(gotBytes) != decryptFixturePlaintext {
		t.Fatalf("unexpected plaintext output %q", gotBytes)
	}
	if !strings.Contains(stdout.String(), "payload_unlocked=false") || !strings.Contains(stdout.String(), "decrypt_complete=true") {
		t.Fatalf("unexpected stdout: %s", stdout.String())
	}
}

func TestRunDecryptFileEncryptedPayloadWithManualSigner(t *testing.T) {
	now := time.Date(2026, 3, 24, 13, 0, 0, 0, time.UTC)
	tempDir := t.TempDir()

	doc := loadFixtureDoc(t, "decrypt-file-encrypted.qrm")
	qrmPath := copyFixtureQRM(t, tempDir, "decrypt-file-encrypted.qrm", "phase3c-encrypted.qrm")
	ciphertextPath := copyFixtureFile(t, "decrypt-file-ciphertext.bin", filepath.Join(tempDir, "ciphertext.enc"))
	outputPath := filepath.Join(tempDir, "restored.txt")

	challenge, err := buildUnlockChallenge(doc)
	if err != nil {
		t.Fatalf("build unlock challenge: %v", err)
	}
	privateKey := mustPrivateKey(t, "1111111111111111111111111111111111111111111111111111111111111111")
	signature := mustPersonalSign(t, privateKey, challenge)

	var stdout bytes.Buffer
	err = run(
		[]string{"decrypt-file", "--qrm", qrmPath, "--signer", "manual", "--file-id", decryptFixtureFileID, "--ciphertext", ciphertextPath, "--output", outputPath},
		&stdout,
		ioDiscard{},
		strings.NewReader(signature+"\n"+decryptFixtureKey+"\n"),
		now,
	)
	if err != nil {
		t.Fatalf("decrypt-file encrypted: %v", err)
	}

	gotBytes, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	if string(gotBytes) != decryptFixturePlaintext {
		t.Fatalf("unexpected plaintext output %q", gotBytes)
	}
	if !strings.Contains(stdout.String(), "payload_unlocked=true") || !strings.Contains(stdout.String(), "wallet_address=") {
		t.Fatalf("unexpected stdout: %s", stdout.String())
	}
}

func TestRunDecryptFileEncryptedPayloadRequiresSigner(t *testing.T) {
	now := time.Date(2026, 3, 24, 14, 0, 0, 0, time.UTC)
	tempDir := t.TempDir()

	qrmPath := copyFixtureQRM(t, tempDir, "decrypt-file-encrypted.qrm", "phase3c-encrypted.qrm")
	ciphertextPath := copyFixtureFile(t, "decrypt-file-ciphertext.bin", filepath.Join(tempDir, "ciphertext.enc"))
	outputPath := filepath.Join(tempDir, "restored.txt")

	err := run(
		[]string{"decrypt-file", "--qrm", qrmPath, "--file-id", decryptFixtureFileID, "--ciphertext", ciphertextPath, "--output", outputPath},
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

	qrmPath := copyFixtureQRM(t, tempDir, "decrypt-file-plaintext.qrm", "phase3c-plaintext.qrm")
	ciphertextPath := copyFixtureFile(t, "decrypt-file-ciphertext.bin", filepath.Join(tempDir, "ciphertext.bin"))
	outputPath := filepath.Join(tempDir, "restored.txt")

	err := run(
		[]string{"decrypt-file", "--qrm", qrmPath, "--file-id", "00000000-0000-4000-8000-000000009999", "--ciphertext", ciphertextPath, "--output", outputPath},
		ioDiscard{},
		ioDiscard{},
		strings.NewReader(decryptFixtureKey+"\n"),
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
