package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

const (
	recoveryMapSchema                     = "qave.recovery-map.v1"
	recoveryPackageSchemaVersion          = "qave.recovery-package.v1"
	challengeVersionLine                  = "qave-recovery:v1"
	challengePurpose                      = "unlock_recovery_payload"
	sessionChallengeVersionLine           = "qave-recovery-export-session:v1"
	sessionChallengePurpose               = "enable_recovery_map_export_session"
	unlockKDFInfo                         = "qave-recovery-payload-unlock-key/v1"
	sessionSeedKDFInfo                    = "qave-recovery-export-session-seed/v1"
	payloadProtectionLegacyPlaintext      = "legacy_plaintext"
	payloadProtectionWalletBoundEncrypted = "wallet_bound_encrypted"
	signingScopeLegacyPerExport           = "legacy_per_export"
	signingScopeSessionBoundV1            = "session_bound_v1"
	payloadLockedCode                     = "PAYLOAD_LOCKED"
	packageStructureLegacyRecoveryMap     = "legacy_recovery_map"
	packageStructureRecoveryPackageV1     = "recovery_package_v1"
	packageStructureLockedPayloadUnknown  = "locked_payload_unverified"
)

type recoveryPackageSummary struct {
	Structure            string
	Known                bool
	WrappedKeysPresent   bool
	SnapshotFileCount    int
	FetchSourcesCount    int
	WrappedKeysCount     int
	RequiresWalletAuth   bool
	RequiresRecoveryKey  bool
	RecoverAllMode       string
	LocalDecryptRequired bool
	LocalPackageRequired bool
}

func buildChallenge(doc recoveryMapDocument, nonce string) (string, error) {
	header := doc.Header
	if strings.TrimSpace(header.MapID) == "" ||
		strings.TrimSpace(header.VaultOwner) == "" ||
		strings.TrimSpace(header.VaultStateHash) == "" ||
		strings.TrimSpace(header.GeneratedAt) == "" ||
		strings.TrimSpace(nonce) == "" {
		return "", newCLIError("QRM_CORRUPTED", "challenge inputs are incomplete")
	}

	lines := []string{
		challengeVersionLine,
		"map_id=" + header.MapID,
		"vault_owner=" + normalizeAddress(header.VaultOwner),
		"vault_state_hash=" + header.VaultStateHash,
		"generated_at=" + header.GeneratedAt,
		"nonce=" + nonce,
		"purpose=" + challengePurpose,
	}
	return strings.Join(lines, "\n"), nil
}

func buildChallengeFromDocument(doc recoveryMapDocument) (string, error) {
	return buildChallenge(doc, strings.TrimSpace(doc.Header.PayloadEncryption.Nonce))
}

func buildUnlockChallenge(doc recoveryMapDocument) (string, error) {
	switch signingScopeOf(doc) {
	case signingScopeLegacyPerExport:
		return buildChallengeFromDocument(doc)
	case signingScopeSessionBoundV1:
		challenge := strings.TrimSpace(doc.Header.PayloadEncryption.SigningChallenge)
		if challenge == "" {
			return "", newCLIError("QRM_CORRUPTED", "session-bound qrm is missing signing_challenge")
		}
		return challenge, nil
	default:
		return "", newCLIError("QRM_CORRUPTED", "unknown signing scope")
	}
}

func recoverPersonalSignAddress(challenge string, signatureHex string) (string, error) {
	signatureBytes, err := decodeHexString(signatureHex)
	if err != nil {
		return "", newCLIError("SIGNATURE_INVALID", "signature must be hex encoded")
	}
	if len(signatureBytes) != 65 {
		return "", newCLIError("SIGNATURE_INVALID", "signature must be 65 bytes")
	}

	sig := append([]byte(nil), signatureBytes...)
	if sig[64] >= 27 {
		sig[64] -= 27
	}
	if sig[64] > 1 {
		return "", newCLIError("SIGNATURE_INVALID", "signature recovery id must be 27/28 or 0/1")
	}

	msg := []byte(challenge)
	prefix := fmt.Sprintf("\x19Ethereum Signed Message:\n%d", len(msg))
	digest := crypto.Keccak256([]byte(prefix), msg)

	pubKey, err := crypto.SigToPub(digest, sig)
	if err != nil {
		return "", newCLIError("SIGNATURE_INVALID", "unable to recover address from signature")
	}
	return normalizeAddress(crypto.PubkeyToAddress(*pubKey).Hex()), nil
}

func deriveUnlockKey(doc recoveryMapDocument, challenge string, signatureHex string) ([]byte, error) {
	switch signingScopeOf(doc) {
	case signingScopeLegacyPerExport:
		return deriveLegacyUnlockKey(doc, challenge, signatureHex)
	case signingScopeSessionBoundV1:
		sessionSeed, err := deriveSessionExportSeed(challenge, signatureHex, doc.Header.VaultOwner)
		if err != nil {
			return nil, err
		}
		return derivePayloadKeyFromSessionSeed(doc, sessionSeed)
	default:
		return nil, newCLIError("QRM_CORRUPTED", "unknown signing scope")
	}
}

func deriveLegacyUnlockKey(doc recoveryMapDocument, challenge string, signatureHex string) ([]byte, error) {
	signatureBytes, err := decodeHexString(signatureHex)
	if err != nil {
		return nil, newCLIError("SIGNATURE_INVALID", "signature must be hex encoded")
	}

	header := doc.Header
	normalizedOwner := normalizeAddress(header.VaultOwner)
	challengeHash := sha256.Sum256([]byte(challenge))
	signatureHash := sha256.Sum256(signatureBytes)

	saltInput := fmt.Sprintf(
		"qave-recovery-cli:v1\nmap_id=%s\nvault_owner=%s\nvault_state_hash=%s",
		header.MapID,
		normalizedOwner,
		header.VaultStateHash,
	)
	saltHash := sha256.Sum256([]byte(saltInput))

	ikmInput := strings.Join([]string{
		"qave-recovery-unlock:v1",
		"signature_hash=" + hex.EncodeToString(signatureHash[:]),
		"challenge_hash=" + hex.EncodeToString(challengeHash[:]),
		"vault_owner=" + normalizedOwner,
		"map_id=" + header.MapID,
		"vault_state_hash=" + header.VaultStateHash,
	}, "\n")
	ikmHash := sha256.Sum256([]byte(ikmInput))

	key, err := hkdf.Key(sha256.New, ikmHash[:], saltHash[:], unlockKDFInfo, 32)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func deriveSessionExportSeed(sessionChallenge string, signatureHex string, walletAddress string) ([]byte, error) {
	signatureBytes, err := decodeHexString(signatureHex)
	if err != nil {
		return nil, newCLIError("SIGNATURE_INVALID", "signature must be hex encoded")
	}

	normalizedWallet := normalizeAddress(walletAddress)
	if normalizedWallet == "" {
		return nil, newCLIError("QRM_CORRUPTED", "wallet address is missing for session-bound unlock")
	}

	sessionChallengeHash := sha256.Sum256([]byte(sessionChallenge))
	signatureHash := sha256.Sum256(signatureBytes)

	saltInput := strings.Join([]string{
		sessionChallengeVersionLine,
		"wallet=" + normalizedWallet,
	}, "\n")
	saltHash := sha256.Sum256([]byte(saltInput))

	ikmInput := strings.Join([]string{
		"qave-recovery-export-session-seed:v1",
		"signature_hash=" + hex.EncodeToString(signatureHash[:]),
		"session_challenge_hash=" + hex.EncodeToString(sessionChallengeHash[:]),
		"wallet=" + normalizedWallet,
	}, "\n")
	ikmHash := sha256.Sum256([]byte(ikmInput))

	key, err := hkdf.Key(sha256.New, ikmHash[:], saltHash[:], sessionSeedKDFInfo, 32)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func derivePayloadKeyFromSessionSeed(doc recoveryMapDocument, sessionSeed []byte) ([]byte, error) {
	header := doc.Header
	normalizedOwner := normalizeAddress(header.VaultOwner)
	if normalizedOwner == "" {
		return nil, newCLIError("QRM_CORRUPTED", "vault_owner is missing for session-bound unlock")
	}

	sessionSeedHash := sha256.Sum256(sessionSeed)
	saltInput := strings.Join([]string{
		"qave-recovery-session-bound:v1",
		"map_id=" + header.MapID,
		"vault_owner=" + normalizedOwner,
		"vault_state_hash=" + header.VaultStateHash,
		"nonce=" + header.PayloadEncryption.Nonce,
	}, "\n")
	saltHash := sha256.Sum256([]byte(saltInput))

	ikmInput := strings.Join([]string{
		"qave-recovery-session-bound-payload-key:v1",
		"session_seed_hash=" + hex.EncodeToString(sessionSeedHash[:]),
		"map_id=" + header.MapID,
		"vault_owner=" + normalizedOwner,
		"vault_state_hash=" + header.VaultStateHash,
		"nonce=" + header.PayloadEncryption.Nonce,
	}, "\n")
	ikmHash := sha256.Sum256([]byte(ikmInput))

	key, err := hkdf.Key(sha256.New, ikmHash[:], saltHash[:], unlockKDFInfo, 32)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func decryptPayload(doc recoveryMapDocument, key []byte) (recoveryMapPayload, error) {
	switch payloadProtectionOf(doc) {
	case payloadProtectionLegacyPlaintext:
		if doc.Payload == nil {
			return recoveryMapPayload{}, newCLIError("QRM_CORRUPTED", "legacy plaintext qrm is missing payload")
		}
		return *doc.Payload, nil
	case payloadProtectionWalletBoundEncrypted:
		ciphertext, err := decodeBase64String(doc.PayloadCiphertext)
		if err != nil {
			return recoveryMapPayload{}, newCLIError("QRM_CORRUPTED", "payload_ciphertext must be base64 encoded")
		}
		tag, err := decodeBase64String(doc.PayloadTag)
		if err != nil {
			return recoveryMapPayload{}, newCLIError("QRM_CORRUPTED", "payload_tag must be base64 encoded")
		}
		if len(tag) != aesGCMTagLength {
			return recoveryMapPayload{}, newCLIError("QRM_CORRUPTED", "payload_tag must be 16 bytes")
		}

		plaintext, err := openPayloadBytes(doc, key, append(ciphertext, tag...))
		if err != nil {
			return recoveryMapPayload{}, err
		}

		var payload recoveryMapPayload
		if err := json.Unmarshal(plaintext, &payload); err != nil {
			return recoveryMapPayload{}, newCLIError("QRM_CORRUPTED", "decrypted payload is not valid json")
		}
		return payload, nil
	default:
		return recoveryMapPayload{}, newCLIError("QRM_CORRUPTED", "unknown payload protection mode")
	}
}

func inspectRecoveryPackage(doc recoveryMapDocument, payload *recoveryMapPayload) recoveryPackageSummary {
	if payload == nil {
		payload = doc.Payload
	}
	if payload == nil {
		return recoveryPackageSummary{
			Structure: packageStructureLockedPayloadUnknown,
			Known:     false,
		}
	}

	hasSnapshot := payload.Snapshot != nil &&
		(strings.TrimSpace(payload.Snapshot.SchemaVersion) != "" ||
			strings.TrimSpace(payload.Snapshot.PackageID) != "" ||
			strings.TrimSpace(payload.Snapshot.RecoveryFlowVersion) != "")
	hasFetchSources := payload.FetchSources != nil
	hasWrappedKeys := payload.WrappedKeys != nil
	hasRecoveryPolicy := payload.RecoveryPolicy != nil &&
		(strings.TrimSpace(payload.RecoveryPolicy.RecoverAllMode) != "" ||
			payload.RecoveryPolicy.RequiresWalletAuth ||
			payload.RecoveryPolicy.RequiresRecoveryKey ||
			payload.RecoveryPolicy.LocalDecryptRequired ||
			payload.RecoveryPolicy.LocalPackageRequired)

	if !(hasSnapshot && hasFetchSources && hasWrappedKeys && hasRecoveryPolicy) {
		return recoveryPackageSummary{
			Structure: packageStructureLegacyRecoveryMap,
			Known:     true,
		}
	}

	snapshotFileCount := len(payload.FileIndex)
	if payload.Snapshot != nil && payload.Snapshot.FileCount > 0 {
		snapshotFileCount = payload.Snapshot.FileCount
	}

	summary := recoveryPackageSummary{
		Structure:          packageStructureRecoveryPackageV1,
		Known:              true,
		WrappedKeysPresent: hasWrappedKeys,
		SnapshotFileCount:  snapshotFileCount,
		FetchSourcesCount:  len(payload.FetchSources),
		WrappedKeysCount:   len(payload.WrappedKeys),
	}
	if payload.RecoveryPolicy != nil {
		summary.RequiresWalletAuth = payload.RecoveryPolicy.RequiresWalletAuth
		summary.RequiresRecoveryKey = payload.RecoveryPolicy.RequiresRecoveryKey
		summary.RecoverAllMode = strings.TrimSpace(payload.RecoveryPolicy.RecoverAllMode)
		summary.LocalDecryptRequired = payload.RecoveryPolicy.LocalDecryptRequired
		summary.LocalPackageRequired = payload.RecoveryPolicy.LocalPackageRequired
	}
	return summary
}

func openPayloadBytes(doc recoveryMapDocument, key []byte, sealed []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce, err := decodeBase64String(doc.Header.PayloadEncryption.Nonce)
	if err != nil {
		return nil, newCLIError("QRM_CORRUPTED", "payload nonce must be base64 encoded")
	}
	if len(nonce) != gcm.NonceSize() {
		return nil, newCLIError("QRM_CORRUPTED", "payload nonce length does not match AES-GCM requirements")
	}
	plaintext, err := gcm.Open(nil, nonce, sealed, nil)
	if err != nil {
		return nil, newCLIError("SIGNATURE_INVALID", "derived unlock key could not decrypt payload")
	}
	return plaintext, nil
}

func fingerprintUnlockKey(key []byte) string {
	sum := sha256.Sum256(key)
	return hex.EncodeToString(sum[:8])
}

func decodeHexString(value string) ([]byte, error) {
	trimmed := strings.TrimSpace(value)
	trimmed = strings.TrimPrefix(trimmed, "0x")
	trimmed = strings.TrimPrefix(trimmed, "0X")
	if trimmed == "" {
		return nil, errors.New("empty hex")
	}
	return hex.DecodeString(trimmed)
}

func decodeBase64String(value string) ([]byte, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return nil, errors.New("empty base64")
	}
	return base64.StdEncoding.DecodeString(trimmed)
}

func normalizeAddress(value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return ""
	}
	return strings.ToLower(common.HexToAddress(trimmed).Hex())
}

const aesGCMTagLength = 16
