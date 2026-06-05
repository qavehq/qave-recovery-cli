# Recovery Package Manifest v1 Draft

This document is an initial draft skeleton for an application-independent Recovery Package Manifest v1. It is not a final cryptographic specification.

The manifest is intended to describe what encrypted data must be retrieved, how to verify it, what recovery materials are required, and what instructions a recovery tool should present. Recovery still requires retrievable encrypted data and user-held recovery materials.

The existing Qave `.qrm` package shape uses Qave-specific field names and wallet-bound package behavior. This draft uses neutral field names so other Filecoin-backed applications can map their own recovery packages to the same concepts.

## Draft Top-Level Fields

- `schemaVersion`: draft manifest version identifier.
- `applicationId`: application or implementation identifier.
- `createdAt`: ISO 8601 timestamp for manifest creation.
- `packageId`: optional stable package identifier.
- `files[]`: encrypted file entries.
- `recoveryInstructions`: human-readable and tool-readable recovery steps.
- `limitations`: known limitations for this package or manifest version.

## Draft File Fields

Each `files[]` entry may include:

- `fileId`: application-level file identifier.
- `fileMetadata`: non-sensitive file metadata such as display name, path, size, and media type.
- `contentIdentifiers`: Filecoin/IPFS content identifiers or equivalent retrieval references.
- `providerHints`: optional provider, deal, piece, or retrieval hints where available.
- `encryption`: encryption metadata needed by a recovery tool, without private keys or plaintext recovery keys.
- `integrity`: hashes or checksums used to verify retrieved ciphertext and restored plaintext where appropriate.
- `recoveryNotes`: optional per-file recovery notes.

## Draft Skeleton

```json
{
  "schemaVersion": "recovery-package-manifest.v1-draft",
  "applicationId": "example-application",
  "createdAt": "2026-06-05T00:00:00Z",
  "packageId": "example-package-id",
  "files": [
    {
      "fileId": "example-file-id",
      "fileMetadata": {
        "name": "example.txt",
        "logicalPath": "/example/example.txt",
        "size": 1234,
        "mimeType": "text/plain",
        "createdAt": "2026-06-05T00:00:00Z"
      },
      "contentIdentifiers": [
        {
          "type": "ipfs-cid",
          "value": "bafy-placeholder-cid",
          "role": "encrypted-content"
        }
      ],
      "providerHints": [
        {
          "type": "filecoin-deal-hint",
          "provider": "f0placeholder",
          "dealId": "placeholder-deal-id",
          "pieceCid": "baga-placeholder-piece-cid"
        }
      ],
      "encryption": {
        "status": "draft-placeholder",
        "contentEncryptionAlgorithm": "placeholder",
        "keyWrapping": "placeholder",
        "nonce": "placeholder",
        "additionalAuthenticatedData": "placeholder"
      },
      "integrity": {
        "ciphertextSha256": "placeholder-sha256",
        "plaintextSha256": "placeholder-sha256-optional"
      },
      "recoveryNotes": "Non-sensitive per-file recovery notes."
    }
  ],
  "recoveryInstructions": {
    "requiredMaterials": [
      "recovery package or manifest",
      "required user-held recovery material"
    ],
    "summary": "Retrieve encrypted content, verify integrity, decrypt locally, and write restored files."
  },
  "limitations": [
    "Draft schema, not a final cryptographic specification.",
    "Recovery requires retrievable encrypted data and retained recovery materials."
  ]
}
```

## Content Identifiers

Content identifiers should identify encrypted content, not plaintext. Entries may include IPFS CIDs, Filecoin piece CIDs, dataset references, or application-specific retrieval references. Applications should avoid including private service URLs or credentials in public manifests.

## Provider And Deal Hints

Provider and deal hints are optional. They can help recovery tools find retrieval paths but should not be treated as the only possible retrieval path. Hints may become stale.

## Encryption Metadata

The manifest may describe encryption algorithms, key wrapping method identifiers, nonces or IVs, and associated data required by the recovery tool. It must not contain private keys, wallet seed phrases, plaintext recovery keys, or other secret material.

Cryptographic details remain draft unless already implemented in the repository. Future versions should specify exact algorithms, encodings, validation rules, and compatibility requirements.

## Integrity Checks

Integrity checks may include ciphertext hashes, restored plaintext hashes where safe and appropriate, package signatures, manifest hashes, or per-file checksums. Recovery tools should fail clearly when required integrity checks do not pass.

## Recovery Instructions

Recovery instructions should describe:

- required user-held materials
- expected retrieval path
- local verification steps
- local decryption steps
- restored file output behavior
- known limitations

## Future Fields

Potential future fields include:

- package signature metadata
- retrieval attempt logs
- multi-provider retrieval strategy
- manifest expiration or freshness signals
- schema migration metadata
- external audit metadata
- non-Qave application integration profile
