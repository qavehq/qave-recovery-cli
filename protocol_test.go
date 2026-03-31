package main

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestBuildChallengeFormat(t *testing.T) {
	doc := recoveryMapDocument{
		Header: recoveryMapHeader{
			MapID:          "11111111-2222-3333-4444-555555555555",
			VaultOwner:     "0x123400000000000000000000000000000000abcd",
			VaultStateHash: "deadbeef",
			GeneratedAt:    "2026-03-21T00:00:00Z",
		},
	}

	got, err := buildChallenge(doc, "bm9uY2U=")
	if err != nil {
		t.Fatalf("build challenge: %v", err)
	}

	want := strings.Join([]string{
		"qave-recovery:v1",
		"map_id=11111111-2222-3333-4444-555555555555",
		"vault_owner=0x123400000000000000000000000000000000abcd",
		"vault_state_hash=deadbeef",
		"generated_at=2026-03-21T00:00:00Z",
		"nonce=bm9uY2U=",
		"purpose=unlock_recovery_payload",
	}, "\n")

	if got != want {
		t.Fatalf("unexpected challenge\nwant:\n%s\n\ngot:\n%s", want, got)
	}
}

func TestDeriveUnlockKeyDeterministic(t *testing.T) {
	doc := recoveryMapDocument{
		Header: recoveryMapHeader{
			MapID:          "11111111-2222-3333-4444-555555555555",
			VaultOwner:     "0x123400000000000000000000000000000000abcd",
			VaultStateHash: "deadbeef",
			GeneratedAt:    "2026-03-21T00:00:00Z",
		},
	}
	challenge, err := buildChallenge(doc, "bm9uY2U=")
	if err != nil {
		t.Fatalf("build challenge: %v", err)
	}

	signature := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1b"
	keyA, err := deriveUnlockKey(doc, challenge, signature)
	if err != nil {
		t.Fatalf("derive keyA: %v", err)
	}
	keyB, err := deriveUnlockKey(doc, challenge, signature)
	if err != nil {
		t.Fatalf("derive keyB: %v", err)
	}

	if len(keyA) != 32 || len(keyB) != 32 {
		t.Fatalf("expected 32-byte keys")
	}
	if string(keyA) != string(keyB) {
		t.Fatalf("expected deterministic key derivation")
	}
}

func TestBuildChallengeFromDocumentUsesHeaderNonce(t *testing.T) {
	doc := recoveryMapDocument{
		Header: recoveryMapHeader{
			MapID:          "11111111-2222-3333-4444-555555555555",
			VaultOwner:     "0x123400000000000000000000000000000000abcd",
			VaultStateHash: "deadbeef",
			GeneratedAt:    "2026-03-21T00:00:00Z",
			PayloadEncryption: recoveryPayloadEncryption{
				Nonce: "bm9uY2U=",
			},
		},
	}

	got, err := buildChallengeFromDocument(doc)
	if err != nil {
		t.Fatalf("build challenge from document: %v", err)
	}
	if !strings.Contains(got, "nonce=bm9uY2U=") {
		t.Fatalf("expected challenge nonce from header, got %s", got)
	}
}

func TestBuildUnlockChallengeUsesSessionSigningChallengeWhenConfigured(t *testing.T) {
	doc := recoveryMapDocument{
		Header: recoveryMapHeader{
			PayloadEncryption: recoveryPayloadEncryption{
				SigningScope:     signingScopeSessionBoundV1,
				SigningChallenge: "qave-recovery-export-session:v1\nwallet=0x1234\nissued_at=2026-03-21T00:00:00Z\nnonce=abc\npurpose=enable_recovery_map_export_session",
			},
		},
	}

	got, err := buildUnlockChallenge(doc)
	if err != nil {
		t.Fatalf("build unlock challenge: %v", err)
	}
	if got != doc.Header.PayloadEncryption.SigningChallenge {
		t.Fatalf("expected session signing challenge, got %q", got)
	}
}

func TestDeriveSessionExportSeedDeterministic(t *testing.T) {
	challenge := strings.Join([]string{
		sessionChallengeVersionLine,
		"wallet=0x123400000000000000000000000000000000abcd",
		"issued_at=2026-03-21T00:00:00Z",
		"nonce=abc123",
		"purpose=" + sessionChallengePurpose,
	}, "\n")
	signature := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1b"

	seedA, err := deriveSessionExportSeed(challenge, signature, "0x123400000000000000000000000000000000abcd")
	if err != nil {
		t.Fatalf("derive seedA: %v", err)
	}
	seedB, err := deriveSessionExportSeed(challenge, signature, "0x123400000000000000000000000000000000ABCD")
	if err != nil {
		t.Fatalf("derive seedB: %v", err)
	}

	if len(seedA) != 32 || len(seedB) != 32 {
		t.Fatalf("expected 32-byte session seeds")
	}
	if string(seedA) != string(seedB) {
		t.Fatalf("expected deterministic session seed derivation")
	}
}

func TestEncryptDecryptPayloadRoundTrip(t *testing.T) {
	doc := recoveryMapDocument{
		Header: recoveryMapHeader{
			MapID:          "11111111-2222-3333-4444-555555555555",
			VaultOwner:     "0x123400000000000000000000000000000000abcd",
			VaultStateHash: "deadbeef",
			GeneratedAt:    "2026-03-21T00:00:00Z",
			PayloadEncryption: recoveryPayloadEncryption{
				Algorithm:         "AES-256-GCM",
				KDF:               "HKDF-SHA256",
				Nonce:             base64.StdEncoding.EncodeToString([]byte("0123456789ab")),
				PayloadProtection: payloadProtectionWalletBoundEncrypted,
				Encoding:          "base64",
			},
		},
	}
	payload := recoveryMapPayload{
		FWSSNetwork:    "phase2-reserved",
		FWSSAPIVersion: "v1",
		FileIndex: []recoveryMapFileIndex{
			{
				Name:   "alpha.txt",
				Size:   12,
				CID:    "piece-alpha",
				Status: "stored",
				StorageRefs: []recoveryMapStorageRef{
					{Kind: "provider_operation_ref", Value: "op-2"},
					{Kind: "bucket", Value: "default"},
				},
				UploadedAt: "2026-03-21T00:00:00Z",
				ExpiresAt:  "2099-01-01T00:00:00Z",
			},
		},
	}
	key := []byte("0123456789abcdef0123456789abcdef")

	ciphertext, tag, err := encryptPayload(doc, payload, key)
	if err != nil {
		t.Fatalf("encrypt payload: %v", err)
	}
	doc.PayloadCiphertext = ciphertext
	doc.PayloadTag = tag

	got, err := decryptPayload(doc, key)
	if err != nil {
		t.Fatalf("decrypt payload: %v", err)
	}
	if got.FWSSNetwork != payload.FWSSNetwork || got.FWSSAPIVersion != payload.FWSSAPIVersion || len(got.FileIndex) != 1 {
		t.Fatalf("unexpected decrypted payload: %#v", got)
	}
	if got.FileIndex[0].StorageRefs[0].Kind != "bucket" {
		t.Fatalf("expected canonical storage ref ordering, got %#v", got.FileIndex[0].StorageRefs)
	}
}
