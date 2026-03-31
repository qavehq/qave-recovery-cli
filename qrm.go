package main

import (
	"encoding/json"
	"os"
	"strings"
	"time"
)

type recoveryMapDocument struct {
	Header            recoveryMapHeader   `json:"header"`
	Payload           *recoveryMapPayload `json:"payload,omitempty"`
	PayloadCiphertext string              `json:"payload_ciphertext,omitempty"`
	PayloadTag        string              `json:"payload_tag,omitempty"`
}

type recoveryMapHeader struct {
	Schema                string                    `json:"schema"`
	MapID                 string                    `json:"map_id"`
	GeneratedAt           string                    `json:"generated_at"`
	VaultOwner            string                    `json:"vault_owner"`
	VaultStateHash        string                    `json:"vault_state_hash"`
	SubscriptionExpiresAt string                    `json:"subscription_expires_at"`
	PayloadEncryption     recoveryPayloadEncryption `json:"payload_encryption"`
}

type recoveryPayloadEncryption struct {
	Algorithm           string `json:"algorithm"`
	KDF                 string `json:"kdf"`
	Nonce               string `json:"nonce"`
	Binding             string `json:"binding"`
	PayloadProtection   string `json:"payload_protection,omitempty"`
	Encoding            string `json:"encoding,omitempty"`
	SigningScope        string `json:"signing_scope,omitempty"`
	SigningScopeVersion string `json:"signing_scope_version,omitempty"`
	SigningChallenge    string `json:"signing_challenge,omitempty"`
}

type recoveryMapPayload struct {
	Snapshot       *recoveryPackageSnapshot       `json:"snapshot,omitempty"`
	FileIndex      []recoveryMapFileIndex         `json:"file_index"`
	FetchSources   []recoveryPackageFetchSource   `json:"fetch_sources,omitempty"`
	WrappedKeys    []recoveryPackageWrappedKey    `json:"wrapped_keys,omitempty"`
	RecoveryPolicy *recoveryPackageRecoveryPolicy `json:"recovery_policy,omitempty"`
	FWSSNetwork    string                         `json:"fwss_network"`
	FWSSAPIVersion string                         `json:"fwss_api_version"`
}

type recoveryPackageSnapshot struct {
	SchemaVersion         string                      `json:"schema_version"`
	PackageID             string                      `json:"package_id"`
	MapID                 string                      `json:"map_id,omitempty"`
	VaultOwner            string                      `json:"vault_owner"`
	VaultStateHash        string                      `json:"vault_state_hash"`
	GeneratedAt           string                      `json:"generated_at"`
	SubscriptionExpiresAt string                      `json:"subscription_expires_at"`
	FileCount             int                         `json:"file_count"`
	PackageProtectionMode string                      `json:"package_protection_mode"`
	RecoveryFlowVersion   string                      `json:"recovery_flow_version"`
	RecoveryKDFProfiles   []recoveryPackageKDFProfile `json:"recovery_kdf_profiles,omitempty"`
}

type recoveryPackageKDFProfile struct {
	MaterialVersion int                      `json:"material_version"`
	KDFAlgorithm    string                   `json:"kdf_algorithm"`
	KDFSalt         string                   `json:"kdf_salt"`
	KDFParams       recoveryPackageKDFParams `json:"kdf_params"`
	KDFVersion      int                      `json:"kdf_version"`
}

type recoveryPackageKDFParams struct {
	Iterations       int    `json:"iterations"`
	Hash             string `json:"hash"`
	DerivedKeyLength int    `json:"derived_key_length"`
}

type recoveryPackageFetchSource struct {
	FileID                 string  `json:"file_id"`
	SourceType             string  `json:"source_type"`
	SourceRef              string  `json:"source_ref"`
	BackendRef             *string `json:"backend_ref"`
	PieceRef               *string `json:"piece_ref"`
	CID                    *string `json:"cid"`
	DatasetRef             *string `json:"dataset_ref"`
	FetchCapabilityVersion string  `json:"fetch_capability_version"`
}

type recoveryPackageWrappedKey struct {
	RecoveryMaterialVersion *int    `json:"recovery_material_version,omitempty"`
	FileID                  string  `json:"file_id"`
	WrappedFileKey          *string `json:"wrapped_file_key"`
	KeyWrapAlgorithm        *string `json:"key_wrap_algorithm"`
	KeyWrapVersion          int     `json:"key_wrap_version"`
	Nonce                   *string `json:"nonce"`
	IV                      *string `json:"iv"`
	AAD                     *string `json:"aad"`
	Tag                     *string `json:"tag"`
	KeyMaterialVersion      int     `json:"key_material_version"`
}

type recoveryPackageRecoveryPolicy struct {
	RequiresWalletAuth     bool   `json:"requires_wallet_auth"`
	RequiresRecoveryKey    bool   `json:"requires_recovery_key"`
	TrustedDeviceSupported bool   `json:"trusted_device_supported"`
	RecoverAllMode         string `json:"recover_all_mode"`
	LocalDecryptRequired   bool   `json:"local_decrypt_required"`
	LocalPackageRequired   bool   `json:"local_package_required"`
}

type recoveryMapFileIndex struct {
	FileID                  string                            `json:"file_id,omitempty"`
	FileName                string                            `json:"file_name,omitempty"`
	LogicalPath             string                            `json:"logical_path,omitempty"`
	Name                    string                            `json:"name"`
	Size                    int64                             `json:"size"`
	MIMEType                *string                           `json:"mime_type,omitempty"`
	CID                     string                            `json:"cid"`
	StorageRefs             []recoveryMapStorageRef           `json:"storage_refs"`
	UploadedAt              string                            `json:"uploaded_at"`
	SnapshotIndex           int                               `json:"snapshot_index,omitempty"`
	ExpiresAt               string                            `json:"expires_at"`
	Status                  string                            `json:"status"`
	Encryption              recoveryMapFileEncryption         `json:"encryption,omitempty"`
	ContentEncryption       *recoveryPackageContentEncryption `json:"content_encryption,omitempty"`
	RecoveryMaterialVersion *int                              `json:"recovery_material_version,omitempty"`
}

type recoveryPackageContentEncryption struct {
	EncryptionVersion          int    `json:"encryption_version"`
	ContentEncryptionAlgorithm string `json:"content_encryption_algorithm"`
	ContentEncryptionIV        string `json:"content_encryption_iv"`
}

type recoveryMapStorageRef struct {
	Kind  string `json:"kind"`
	Value string `json:"value"`
}

type recoveryMapFileEncryption struct {
	Mode                string `json:"mode"`
	KeyMaterialIncluded bool   `json:"key_material_included"`
	KeyDerivation       string `json:"key_derivation"`
	WalletBinding       string `json:"wallet_binding"`
}

func loadRecoveryMap(path string) (recoveryMapDocument, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return recoveryMapDocument{}, newCLIError("QRM_CORRUPTED", "unable to read qrm file")
	}

	var doc recoveryMapDocument
	if err := json.Unmarshal(raw, &doc); err != nil {
		return recoveryMapDocument{}, newCLIError("QRM_CORRUPTED", "qrm is not valid json")
	}
	return doc, nil
}

func validateRecoveryMap(doc recoveryMapDocument, now time.Time) error {
	if strings.TrimSpace(doc.Header.Schema) != recoveryMapSchema {
		return newCLIError("QRM_SCHEMA_UNSUPPORTED", "unsupported qrm schema")
	}

	requiredHeaderFields := []string{
		doc.Header.MapID,
		doc.Header.GeneratedAt,
		doc.Header.VaultOwner,
		doc.Header.VaultStateHash,
		doc.Header.SubscriptionExpiresAt,
		doc.Header.PayloadEncryption.Algorithm,
		doc.Header.PayloadEncryption.KDF,
		doc.Header.PayloadEncryption.Nonce,
	}
	for _, value := range requiredHeaderFields {
		if strings.TrimSpace(value) == "" {
			return newCLIError("QRM_CORRUPTED", "qrm required header fields are missing")
		}
	}

	expiresAt, err := time.Parse(time.RFC3339Nano, doc.Header.SubscriptionExpiresAt)
	if err != nil {
		return newCLIError("QRM_CORRUPTED", "subscription_expires_at must be valid ISO8601")
	}
	if !expiresAt.After(now.UTC()) {
		return newCLIError("QRM_EXPIRED", "qrm subscription window has expired")
	}

	switch payloadProtectionOf(doc) {
	case payloadProtectionLegacyPlaintext:
		if doc.Payload == nil {
			return newCLIError("QRM_CORRUPTED", "legacy plaintext qrm is missing payload")
		}
		if strings.TrimSpace(doc.Payload.FWSSNetwork) == "" || strings.TrimSpace(doc.Payload.FWSSAPIVersion) == "" {
			return newCLIError("QRM_CORRUPTED", "legacy plaintext payload is incomplete")
		}
	case payloadProtectionWalletBoundEncrypted:
		if strings.TrimSpace(doc.PayloadCiphertext) == "" || strings.TrimSpace(doc.PayloadTag) == "" {
			return newCLIError("QRM_CORRUPTED", "encrypted qrm is missing payload ciphertext material")
		}
		if strings.TrimSpace(doc.Header.PayloadEncryption.Encoding) == "" {
			return newCLIError("QRM_CORRUPTED", "encrypted qrm is missing payload encoding")
		}
	default:
		return newCLIError("QRM_CORRUPTED", "unknown payload protection mode")
	}

	switch signingScopeOf(doc) {
	case signingScopeLegacyPerExport:
	case signingScopeSessionBoundV1:
		if strings.TrimSpace(doc.Header.PayloadEncryption.SigningChallenge) == "" {
			return newCLIError("QRM_CORRUPTED", "session-bound qrm is missing signing_challenge")
		}
		if version := strings.TrimSpace(doc.Header.PayloadEncryption.SigningScopeVersion); version != "" && version != "v1" {
			return newCLIError("QRM_CORRUPTED", "unsupported session-bound signing_scope_version")
		}
	default:
		return newCLIError("QRM_CORRUPTED", "unknown signing scope")
	}

	return nil
}

func payloadProtectionOf(doc recoveryMapDocument) string {
	explicit := strings.TrimSpace(doc.Header.PayloadEncryption.PayloadProtection)
	if explicit != "" {
		return explicit
	}
	if doc.Payload != nil {
		return payloadProtectionLegacyPlaintext
	}
	if strings.TrimSpace(doc.PayloadCiphertext) != "" || strings.TrimSpace(doc.PayloadTag) != "" {
		return payloadProtectionWalletBoundEncrypted
	}
	return ""
}

func signingScopeOf(doc recoveryMapDocument) string {
	scope := strings.TrimSpace(doc.Header.PayloadEncryption.SigningScope)
	if scope != "" {
		return scope
	}
	return signingScopeLegacyPerExport
}
