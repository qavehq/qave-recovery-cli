# Recovery Assumptions

This project documents application-independent recovery for encrypted Filecoin-backed data. Recovery is conditional, not guaranteed.

## Required Recovery Materials

A recovery flow may require:

- a recovery package or manifest
- content identifiers and retrieval hints
- the wallet account associated with the package, when wallet binding is used
- the user-held recovery key or other required recovery material
- enough local disk space to retrieve encrypted data and write restored files
- a recovery tool that supports the package version

For Qave recovery packages, the current user-facing flow assumes the user has the `.qrm` Recovery Package, the same wallet account used when the package was created, and the matching Recovery Key.

## Retrievable Encrypted Data

The encrypted data must remain retrievable. Recovery may depend on Filecoin/IPFS retrieval paths, gateways, storage providers, deal information, content identifiers, or provider hints.

If the encrypted data is no longer retrievable from any usable path, the toolkit cannot restore it.

## User-Retained Materials

The user must retain the required recovery package and recovery materials. The toolkit is designed around user-held materials rather than service-side custody of private keys or recovery keys.

If the user loses required recovery materials, recovery may be impossible even if the encrypted data is still stored.

## Independence From The Normal Qave App Path

The recovery workflow is designed to work without relying on the normal Qave frontend/backend API. A recovery drill should be able to test the scenario where those normal application services are unavailable.

This does not mean recovery is fully offline. Retrieval may still require network access and available Filecoin/IPFS retrieval paths, gateways, or providers.

## Limitations

The toolkit does not guarantee recovery when:

- encrypted data is gone or unreachable
- required recovery materials are lost
- the recovery package is corrupted
- package integrity checks fail
- the package uses an unsupported version or unsupported encryption metadata
- external retrieval paths are unavailable
- user-held credentials or wallet access no longer match the package requirements
