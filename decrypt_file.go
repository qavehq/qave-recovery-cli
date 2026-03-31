package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unicode"
)

const (
	recoveryKDFAlgorithmPBKDF2SHA256 = "PBKDF2-HMAC-SHA-256"
	recoveryKDFHashSHA256            = "SHA-256"
	recoveryKDFVersion1              = 1
	recoveryDerivedKeyLengthBytes    = 32
	recoveryWrapAlgorithmAES256GCM   = "AES-256-GCM"
	recoveryWrapVersion1             = 1
	recoveryKeyMaterialVersion1      = 1
	recoveryKeyAlphabet              = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"
	recoveryKeyRawLength             = 20
	wrapIVLengthBytes                = 12
	fileKeyLengthBytes               = 32
	wrappedFileKeyLengthBytes        = 48
)

var publicFileIDPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

type decryptFileOptions struct {
	QRMPath        string
	Signer         string
	FileID         string
	CiphertextPath string
	OutputPath     string
}

func runDecryptFile(args []string, stdout io.Writer, stdin io.Reader, now time.Time) error {
	options, err := parseDecryptFileArgs(args)
	if err != nil {
		return err
	}

	doc, err := loadRecoveryMap(options.QRMPath)
	if err != nil {
		return err
	}
	if err := validateRecoveryMap(doc, now); err != nil {
		return err
	}

	reader := bufio.NewReader(stdin)
	payload, recoveredAddress, payloadUnlocked, err := resolveDecryptPayload(doc, options.Signer, stdout, reader, now)
	if err != nil {
		return err
	}

	recoveryKey, err := readRecoveryKey(reader, stdout)
	if err != nil {
		return err
	}

	fileEntry, err := selectRecoveryFileByID(payload, options.FileID)
	if err != nil {
		return err
	}
	wrappedKey, err := selectWrappedKeyByFileID(payload, options.FileID)
	if err != nil {
		return err
	}
	profile, err := selectRecoveryProfile(payload, fileEntry, wrappedKey)
	if err != nil {
		return err
	}

	wrapKeyBytes, err := deriveRecoveryWrapKeyBytes(recoveryKey, profile)
	if err != nil {
		return err
	}
	defer zeroBytes(wrapKeyBytes)

	fileKeyBytes, err := unwrapRecoveryFileKey(wrapKeyBytes, wrappedKey)
	if err != nil {
		return err
	}
	defer zeroBytes(fileKeyBytes)

	plaintextBytes, err := decryptLocalCiphertext(options.CiphertextPath, fileEntry, fileKeyBytes)
	if err != nil {
		return err
	}
	defer zeroBytes(plaintextBytes)

	if err := writeDecryptedOutput(options.OutputPath, plaintextBytes); err != nil {
		return err
	}

	if payloadUnlocked {
		_, _ = fmt.Fprintf(stdout, "wallet_address=%s\n", recoveredAddress)
	}
	_, _ = fmt.Fprintf(stdout, "payload_unlocked=%t\n", payloadUnlocked)
	_, _ = fmt.Fprintf(stdout, "file_id=%s\n", fileEntry.FileID)
	_, _ = fmt.Fprintf(stdout, "ciphertext_path=%s\n", options.CiphertextPath)
	_, _ = fmt.Fprintf(stdout, "output_path=%s\n", options.OutputPath)
	_, _ = fmt.Fprintf(stdout, "plaintext_bytes=%d\n", len(plaintextBytes))
	_, _ = fmt.Fprintln(stdout, "decrypt_complete=true")
	return nil
}

func parseDecryptFileArgs(args []string) (decryptFileOptions, error) {
	if len(args) == 0 {
		return decryptFileOptions{}, newCLIError("USAGE", "decrypt-file requires: qave-recovery-cli decrypt-file --qrm <map.qrm> --file-id <public_id> --ciphertext <path> --output <path> [--signer <metamask|manual>]")
	}

	var options decryptFileOptions
	for index := 0; index < len(args); index += 2 {
		if index+1 >= len(args) {
			return decryptFileOptions{}, newCLIError("USAGE", "decrypt-file flags must be key/value pairs")
		}
		key := strings.TrimSpace(args[index])
		value := strings.TrimSpace(args[index+1])
		switch key {
		case "--qrm":
			options.QRMPath = value
		case "--signer":
			options.Signer = strings.ToLower(value)
		case "--file-id":
			options.FileID = value
		case "--ciphertext":
			options.CiphertextPath = value
		case "--output":
			options.OutputPath = value
		default:
			return decryptFileOptions{}, newCLIError("USAGE", "unsupported decrypt-file flag "+key)
		}
	}

	if options.QRMPath == "" || options.FileID == "" || options.CiphertextPath == "" || options.OutputPath == "" {
		return decryptFileOptions{}, newCLIError("USAGE", "decrypt-file requires --qrm, --file-id, --ciphertext, and --output")
	}
	if options.Signer != "" && options.Signer != "metamask" && options.Signer != "manual" {
		return decryptFileOptions{}, newCLIError("UNSUPPORTED_SIGNER", "supported signers are metamask and manual")
	}
	if !publicFileIDPattern.MatchString(strings.TrimSpace(options.FileID)) {
		return decryptFileOptions{}, newCLIError("INVALID_FILE_ID", "file_id must be a canonical lowercase UUID v4")
	}
	return options, nil
}

func resolveDecryptPayload(doc recoveryMapDocument, signer string, stdout io.Writer, stdin *bufio.Reader, now time.Time) (recoveryMapPayload, string, bool, error) {
	switch payloadProtectionOf(doc) {
	case payloadProtectionLegacyPlaintext:
		if doc.Payload == nil {
			return recoveryMapPayload{}, "", false, newCLIError("QRM_CORRUPTED", "legacy plaintext qrm is missing payload")
		}
		return *doc.Payload, "", false, nil
	case payloadProtectionWalletBoundEncrypted:
		if signer == "" {
			return recoveryMapPayload{}, "", false, newCLIError("UNLOCK_REQUIRED", "encrypted qrm requires --signer <metamask|manual>")
		}
		result, err := unlockRecoveryMap(doc, signer, stdout, stdin, now)
		if err != nil {
			return recoveryMapPayload{}, "", false, err
		}
		return result.payload, result.recoveredAddress, true, nil
	default:
		return recoveryMapPayload{}, "", false, newCLIError("QRM_CORRUPTED", "unknown payload protection mode")
	}
}

func readRecoveryKey(stdin *bufio.Reader, stdout io.Writer) (string, error) {
	_, _ = fmt.Fprint(stdout, "paste recovery key (hyphens/spaces optional): ")
	value, err := stdin.ReadString('\n')
	if err != nil && err != io.EOF {
		return "", err
	}
	return parseRecoveryKeyMaterialCLI(value)
}

func selectRecoveryFileByID(payload recoveryMapPayload, fileID string) (recoveryMapFileIndex, error) {
	targetID := strings.TrimSpace(fileID)
	if targetID == "" {
		return recoveryMapFileIndex{}, newCLIError("INVALID_FILE_ID", "file_id is required")
	}

	var matches []recoveryMapFileIndex
	for _, file := range payload.FileIndex {
		if strings.TrimSpace(file.FileID) == targetID {
			matches = append(matches, file)
		}
	}
	switch len(matches) {
	case 0:
		return recoveryMapFileIndex{}, newCLIError("FILE_ID_NOT_FOUND", "file_id was not found in qrm file_index")
	case 1:
		return matches[0], nil
	default:
		return recoveryMapFileIndex{}, newCLIError("QRM_CORRUPTED", "file_id is not unique in qrm file_index")
	}
}

func selectWrappedKeyByFileID(payload recoveryMapPayload, fileID string) (recoveryPackageWrappedKey, error) {
	targetID := strings.TrimSpace(fileID)
	var matches []recoveryPackageWrappedKey
	for _, wrappedKey := range payload.WrappedKeys {
		if strings.TrimSpace(wrappedKey.FileID) == targetID {
			matches = append(matches, wrappedKey)
		}
	}
	switch len(matches) {
	case 0:
		return recoveryPackageWrappedKey{}, newCLIError("WRAPPED_KEY_NOT_FOUND", "wrapped key entry was not found for file_id")
	case 1:
		return matches[0], nil
	default:
		return recoveryPackageWrappedKey{}, newCLIError("QRM_CORRUPTED", "wrapped key entry is not unique for file_id")
	}
}

func selectRecoveryProfile(payload recoveryMapPayload, file recoveryMapFileIndex, wrappedKey recoveryPackageWrappedKey) (recoveryPackageKDFProfile, error) {
	if wrappedKey.RecoveryMaterialVersion == nil || *wrappedKey.RecoveryMaterialVersion <= 0 {
		return recoveryPackageKDFProfile{}, newCLIError("RECOVERY_PROFILE_NOT_FOUND", "wrapped key is missing recovery_material_version")
	}
	if file.RecoveryMaterialVersion != nil && *file.RecoveryMaterialVersion != *wrappedKey.RecoveryMaterialVersion {
		return recoveryPackageKDFProfile{}, newCLIError("QRM_CORRUPTED", "file recovery_material_version does not match wrapped key")
	}
	if payload.Snapshot == nil {
		return recoveryPackageKDFProfile{}, newCLIError("RECOVERY_PROFILE_NOT_FOUND", "qrm snapshot is missing recovery_kdf_profiles")
	}

	targetVersion := *wrappedKey.RecoveryMaterialVersion
	var matches []recoveryPackageKDFProfile
	for _, profile := range payload.Snapshot.RecoveryKDFProfiles {
		if profile.MaterialVersion == targetVersion {
			matches = append(matches, profile)
		}
	}
	switch len(matches) {
	case 0:
		return recoveryPackageKDFProfile{}, newCLIError("RECOVERY_PROFILE_NOT_FOUND", "recovery profile was not found for material_version")
	case 1:
		return matches[0], nil
	default:
		return recoveryPackageKDFProfile{}, newCLIError("QRM_CORRUPTED", "recovery profile is not unique for material_version")
	}
}

func deriveRecoveryWrapKeyBytes(recoveryKey string, profile recoveryPackageKDFProfile) ([]byte, error) {
	if strings.TrimSpace(profile.KDFAlgorithm) != recoveryKDFAlgorithmPBKDF2SHA256 {
		return nil, newCLIError("UNSUPPORTED_RECOVERY_CRYPTO", "unsupported recovery kdf algorithm")
	}
	if profile.KDFVersion != recoveryKDFVersion1 {
		return nil, newCLIError("UNSUPPORTED_RECOVERY_CRYPTO", "unsupported recovery kdf version")
	}
	if strings.TrimSpace(profile.KDFParams.Hash) != recoveryKDFHashSHA256 {
		return nil, newCLIError("UNSUPPORTED_RECOVERY_CRYPTO", "unsupported recovery kdf hash")
	}
	if profile.KDFParams.DerivedKeyLength != recoveryDerivedKeyLengthBytes {
		return nil, newCLIError("UNSUPPORTED_RECOVERY_CRYPTO", "unsupported recovery kdf length")
	}
	if profile.KDFParams.Iterations <= 0 {
		return nil, newCLIError("QRM_CORRUPTED", "recovery kdf iterations must be positive")
	}

	normalizedRecoveryKey, err := parseRecoveryKeyMaterialCLI(recoveryKey)
	if err != nil {
		return nil, err
	}

	recoveryKeyBytes := []byte(normalizedRecoveryKey)
	defer zeroBytes(recoveryKeyBytes)

	saltBytes, err := decodeBase64String(strings.TrimSpace(profile.KDFSalt))
	if err != nil {
		return nil, newCLIError("QRM_CORRUPTED", "recovery kdf salt must be base64 encoded")
	}
	defer zeroBytes(saltBytes)

	return pbkdf2SHA256(recoveryKeyBytes, saltBytes, profile.KDFParams.Iterations, recoveryDerivedKeyLengthBytes), nil
}

func unwrapRecoveryFileKey(wrapKey []byte, wrappedKey recoveryPackageWrappedKey) ([]byte, error) {
	if wrappedKey.WrappedFileKey == nil || strings.TrimSpace(*wrappedKey.WrappedFileKey) == "" {
		return nil, newCLIError("WRAPPED_KEY_NOT_FOUND", "wrapped_file_key is missing for file_id")
	}
	if wrappedKey.KeyWrapAlgorithm == nil || strings.TrimSpace(*wrappedKey.KeyWrapAlgorithm) != recoveryWrapAlgorithmAES256GCM {
		return nil, newCLIError("UNSUPPORTED_RECOVERY_CRYPTO", "unsupported wrapped key algorithm")
	}
	if wrappedKey.KeyWrapVersion != recoveryWrapVersion1 {
		return nil, newCLIError("UNSUPPORTED_RECOVERY_CRYPTO", "unsupported wrapped key version")
	}
	if wrappedKey.KeyMaterialVersion != recoveryKeyMaterialVersion1 {
		return nil, newCLIError("UNSUPPORTED_RECOVERY_CRYPTO", "unsupported key material version")
	}
	if wrappedKey.IV == nil || strings.TrimSpace(*wrappedKey.IV) == "" {
		return nil, newCLIError("WRAPPED_KEY_NOT_FOUND", "wrapped key iv is missing for file_id")
	}
	if hasNonEmptyRecoveryString(wrappedKey.Nonce) || hasNonEmptyRecoveryString(wrappedKey.AAD) || hasNonEmptyRecoveryString(wrappedKey.Tag) {
		return nil, newCLIError("UNSUPPORTED_RECOVERY_CRYPTO", "wrapped key auxiliary nonce/aad/tag fields are not supported in this build")
	}

	sealedBytes, err := decodeBase64String(strings.TrimSpace(*wrappedKey.WrappedFileKey))
	if err != nil {
		return nil, newCLIError("QRM_CORRUPTED", "wrapped_file_key must be base64 encoded")
	}
	defer zeroBytes(sealedBytes)
	if len(sealedBytes) != wrappedFileKeyLengthBytes {
		return nil, newCLIError("QRM_CORRUPTED", "wrapped_file_key length is invalid")
	}

	ivBytes, err := decodeBase64String(strings.TrimSpace(*wrappedKey.IV))
	if err != nil {
		return nil, newCLIError("QRM_CORRUPTED", "wrapped key iv must be base64 encoded")
	}
	defer zeroBytes(ivBytes)
	if len(ivBytes) != wrapIVLengthBytes {
		return nil, newCLIError("QRM_CORRUPTED", "wrapped key iv length is invalid")
	}

	block, err := aes.NewCipher(wrapKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	fileKeyBytes, err := gcm.Open(nil, ivBytes, sealedBytes, nil)
	if err != nil {
		return nil, newCLIError("RECOVERY_KEY_INVALID", "recovery key could not unwrap file key")
	}
	if len(fileKeyBytes) != fileKeyLengthBytes {
		zeroBytes(fileKeyBytes)
		return nil, newCLIError("QRM_CORRUPTED", "unwrapped file key length is invalid")
	}
	return fileKeyBytes, nil
}

func decryptLocalCiphertextFromBytes(ciphertextBytes []byte, file recoveryMapFileIndex, fileKeyBytes []byte) ([]byte, error) {
	if file.ContentEncryption == nil {
		return nil, newCLIError("CONTENT_ENCRYPTION_METADATA_MISSING", "content_encryption metadata is missing for file_id")
	}
	if file.ContentEncryption.EncryptionVersion != 1 {
		return nil, newCLIError("UNSUPPORTED_RECOVERY_CRYPTO", "unsupported content encryption version")
	}
	if strings.TrimSpace(file.ContentEncryption.ContentEncryptionAlgorithm) != recoveryWrapAlgorithmAES256GCM {
		return nil, newCLIError("UNSUPPORTED_RECOVERY_CRYPTO", "unsupported content encryption algorithm")
	}

	ivBytes, err := decodeBase64String(strings.TrimSpace(file.ContentEncryption.ContentEncryptionIV))
	if err != nil {
		return nil, newCLIError("QRM_CORRUPTED", "content_encryption_iv must be base64 encoded")
	}
	defer zeroBytes(ivBytes)
	if len(ivBytes) != wrapIVLengthBytes {
		return nil, newCLIError("QRM_CORRUPTED", "content_encryption_iv length is invalid")
	}

	if len(ciphertextBytes) <= aesGCMTagLength {
		zeroBytes(ciphertextBytes)
		return nil, newCLIError("QRM_CORRUPTED", "ciphertext is shorter than AES-GCM tag length")
	}

	block, err := aes.NewCipher(fileKeyBytes)
	if err != nil {
		zeroBytes(ciphertextBytes)
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		zeroBytes(ciphertextBytes)
		return nil, err
	}
	plaintextBytes, err := gcm.Open(nil, ivBytes, ciphertextBytes, nil)
	zeroBytes(ciphertextBytes)
	if err != nil {
		return nil, newCLIError("CIPHERTEXT_DECRYPT_FAILED", "ciphertext could not be decrypted with the resolved file key")
	}
	if file.Size > 0 && int64(len(plaintextBytes)) != file.Size {
		zeroBytes(plaintextBytes)
		return nil, newCLIError("PLAINTEXT_SIZE_MISMATCH", "decrypted plaintext size does not match qrm file size")
	}
	return plaintextBytes, nil
}

func decryptLocalCiphertext(ciphertextPath string, file recoveryMapFileIndex, fileKeyBytes []byte) ([]byte, error) {
	ciphertextBytes, err := os.ReadFile(ciphertextPath)
	if err != nil {
		return nil, newCLIError("CIPHERTEXT_READ_FAILED", "unable to read ciphertext file")
	}
	return decryptLocalCiphertextFromBytes(ciphertextBytes, file, fileKeyBytes)
}

func writeDecryptedOutput(outputPath string, plaintext []byte) error {
	if strings.TrimSpace(outputPath) == "" {
		return newCLIError("USAGE", "decrypt-file requires --output <path>")
	}
	if _, err := os.Stat(outputPath); err == nil {
		return newCLIError("OUTPUT_EXISTS", "output path already exists")
	} else if !os.IsNotExist(err) {
		return newCLIError("OUTPUT_WRITE_FAILED", "unable to inspect output path")
	}
	if err := os.MkdirAll(filepath.Dir(outputPath), 0o755); err != nil {
		return newCLIError("OUTPUT_WRITE_FAILED", "failed to create output directory")
	}
	if err := os.WriteFile(outputPath, plaintext, 0o600); err != nil {
		return newCLIError("OUTPUT_WRITE_FAILED", "failed to write decrypted output")
	}
	return nil
}

func normalizeRecoveryKeyMaterialCLI(value string) string {
	upper := strings.ToUpper(strings.TrimSpace(value))
	var builder strings.Builder
	builder.Grow(len(upper))
	for _, char := range upper {
		if strings.ContainsRune(recoveryKeyAlphabet, char) {
			builder.WriteRune(char)
		}
	}
	return builder.String()
}

func parseRecoveryKeyMaterialCLI(value string) (string, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return "", newCLIError("RECOVERY_KEY_MISSING", "recovery key is required")
	}

	upper := strings.ToUpper(trimmed)
	var builder strings.Builder
	builder.Grow(len(upper))
	for _, char := range upper {
		switch {
		case char == '-':
			continue
		case unicode.IsSpace(char):
			continue
		case strings.ContainsRune(recoveryKeyAlphabet, char):
			builder.WriteRune(char)
		default:
			return "", newCLIError("RECOVERY_KEY_INVALID_FORMAT", "recovery key contains invalid characters; only letters A-Z without I/L/O and digits 2-9 are allowed")
		}
	}

	normalized := builder.String()
	if normalized == "" {
		return "", newCLIError("RECOVERY_KEY_MISSING", "recovery key is required")
	}
	if len(normalized) != recoveryKeyRawLength {
		return "", newCLIError("RECOVERY_KEY_INVALID_LENGTH", fmt.Sprintf("recovery key must be %d characters after removing spaces and hyphens", recoveryKeyRawLength))
	}
	return normalized, nil
}

func pbkdf2SHA256(password []byte, salt []byte, iterations int, keyLength int) []byte {
	hashLength := sha256.Size
	blockCount := (keyLength + hashLength - 1) / hashLength
	derivedKey := make([]byte, 0, blockCount*hashLength)

	for blockIndex := 1; blockIndex <= blockCount; blockIndex++ {
		u := pbkdf2PRFSHA256(password, salt, blockIndex)
		t := append([]byte(nil), u...)
		for iteration := 1; iteration < iterations; iteration++ {
			nextU := pbkdf2PRFSHA256(password, u, 0)
			zeroBytes(u)
			u = nextU
			for index := range t {
				t[index] ^= u[index]
			}
		}
		zeroBytes(u)
		derivedKey = append(derivedKey, t...)
		zeroBytes(t)
	}

	return derivedKey[:keyLength]
}

func pbkdf2PRFSHA256(password []byte, salt []byte, blockIndex int) []byte {
	mac := hmac.New(sha256.New, password)
	_, _ = mac.Write(salt)
	if blockIndex > 0 {
		var counter [4]byte
		binary.BigEndian.PutUint32(counter[:], uint32(blockIndex))
		_, _ = mac.Write(counter[:])
	}
	return mac.Sum(nil)
}

func hasNonEmptyRecoveryString(value *string) bool {
	return value != nil && strings.TrimSpace(*value) != ""
}

func zeroBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
