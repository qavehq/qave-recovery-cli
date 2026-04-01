package main

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
)

func TestRunVerifyAndUnlockEncryptedPayloadLegacyPerExport(t *testing.T) {
	now := time.Date(2026, 3, 21, 0, 0, 0, 0, time.UTC)
	doc := loadFixtureDoc(t, "verify-unlock-legacy.qrm")
	privateKey := mustPrivateKey(t, "1111111111111111111111111111111111111111111111111111111111111111")
	challenge, err := buildChallengeFromDocument(doc)
	if err != nil {
		t.Fatalf("build challenge: %v", err)
	}
	signature := mustPersonalSign(t, privateKey, challenge)

	tempDir := t.TempDir()
	path := copyFixtureQRM(t, tempDir, "verify-unlock-legacy.qrm", "sample-phase4.qrm")

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
	doc := loadFixtureDoc(t, "verify-unlock-session.qrm")
	privateKey := mustPrivateKey(t, "1111111111111111111111111111111111111111111111111111111111111111")
	signature := mustPersonalSign(t, privateKey, doc.Header.PayloadEncryption.SigningChallenge)

	tempDir := t.TempDir()
	path := copyFixtureQRM(t, tempDir, "verify-unlock-session.qrm", "sample-phase45-session-bound.qrm")

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
	err := run([]string{"unlock", path, "--signer", "manual"}, &unlockOut, ioDiscard{}, strings.NewReader(signature+"\n"), now)
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
	tempDir := t.TempDir()
	path := copyFixtureQRM(t, tempDir, "verify-plaintext-package.qrm", "sample-recovery-package-v1.qrm")

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
	tempDir := t.TempDir()
	path := copyFixtureQRM(t, tempDir, "verify-legacy-map.qrm", "sample-legacy-recovery-map.qrm")

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

func opaqueTestFileID(index int) string {
	return fmt.Sprintf("00000000-0000-4000-8000-%012d", index+1)
}
