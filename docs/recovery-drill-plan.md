# Independent Recovery Drill Plan

This is a draft plan for an independent recovery drill. The drill tests whether recovery can proceed when the normal Qave frontend/backend API is unavailable.

The drill does not prove that every future recovery scenario will succeed. Recovery requires retrievable encrypted data and retained user recovery materials.

## Scenario

Qave normal frontend/backend API is unavailable. The recovery participant attempts to restore files using the recovery package, required user-held recovery materials, and available Filecoin/IPFS retrieval paths, gateways, or providers.

## Inputs Required

- recovery package or manifest
- required user-held recovery materials
- retrieval environment with network access
- recovery CLI build or browser recovery tool build
- expected file list or non-sensitive verification target
- local machine with enough disk space for encrypted retrievals and restored files

For a Qave reference drill, the expected user-held materials are the Qave Recovery Package, the matching wallet account when wallet binding is required, and the matching Recovery Key.

## Expected Flow

1. Confirm the normal Qave frontend/backend API is not used.
2. Open the recovery package locally.
3. Validate package structure and supported version.
4. Identify encrypted content identifiers and retrieval hints.
5. Retrieve encrypted data from available retrieval paths.
6. Verify ciphertext integrity where metadata is available.
7. Collect required recovery material from the user locally.
8. Decrypt locally.
9. Verify restored output where possible.
10. Record non-sensitive results and failure modes.

## CLI Path

- Run package verification.
- Parse manifest or package metadata.
- Attempt retrieval using content identifiers and provider hints.
- Write recovery logs that omit secrets and sensitive recovery material.
- Prompt for required user-held recovery material locally.
- Decrypt locally.
- Write restored files or a restored archive.
- Report success, partial success, or failure with clear reason codes.

## Browser Tool Path

- Import recovery package locally in the browser tool.
- Parse package metadata without sending sensitive material to Qave services.
- Accept required user-held recovery material locally.
- Retrieve encrypted content where supported by the browser workflow.
- Verify package and file integrity where possible.
- Decrypt locally.
- Offer restored file download.
- Show clear local-only errors for unsupported package versions, missing materials, failed retrieval, or integrity failures.

## Verification Steps

- Confirm no normal Qave frontend/backend API calls are required.
- Confirm no private keys, wallet seed phrases, recovery keys, or plaintext file contents appear in logs.
- Confirm encrypted content was retrieved from independent retrieval paths.
- Confirm integrity checks pass before restored output is accepted.
- Confirm restored files match expected names, sizes, hashes, or other non-sensitive acceptance criteria.
- Confirm failure modes are documented when recovery cannot proceed.

## Limitations

- A successful drill does not guarantee all future recovery attempts.
- Recovery can fail if encrypted data is no longer retrievable.
- Recovery can fail if required user-held materials are missing.
- Retrieval paths, gateways, providers, or deal hints may be unavailable or stale.
- Browser recovery may have size, memory, network, or API limitations.
- Some package versions or encryption metadata may require CLI support before browser support.

## Expected Public Report Output

The public report should include:

- drill date and toolkit version or commit reference
- scenario summary
- tools used
- package type and schema version, without sensitive package contents
- retrieval paths tested, using non-sensitive descriptions
- verification checks performed
- recovered output summary, using non-sensitive file descriptions
- limitations encountered
- defects or follow-up work
- confirmation that sensitive recovery materials were not published
