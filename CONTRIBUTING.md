# Contributing

Thank you for helping improve Qave Recovery Toolkit. This project is focused on application-independent recovery for encrypted Filecoin-backed data, with Qave serving as the first reference implementation.

## Project Scope

Good contributions for this repository include:

- recovery package and manifest documentation
- retrieval verification notes
- local verification and decryption workflow improvements
- recovery CLI hardening
- browser recovery tool improvements
- non-sensitive sample recovery package structures
- user and developer documentation
- recovery drill documentation and feedback

Out of scope for this public-good toolkit:

- Qave commercial product features
- billing, subscription, internal dashboard, or production operations logic
- production deployment details
- secrets, private URLs, API keys, credentials, or sensitive recovery packages

## Opening Issues

When opening an issue, include:

- the affected document, tool, or workflow
- the expected behavior
- the actual behavior or gap
- a minimal non-sensitive example, if helpful

Do not include private keys, wallet seed phrases, recovery keys, customer data, production recovery packages, private provider details, or internal service URLs.

## Documentation Contributions

Documentation improvements are welcome, especially when they make recovery assumptions, limitations, or user steps clearer. Please keep claims precise. Do not imply recovery is guaranteed in every scenario. Recovery requires retrievable encrypted data and the user retaining required recovery materials.

## Example Recovery Packages

Example package contributions must use placeholder data only:

- placeholder CIDs
- placeholder provider or deal hints
- fake file metadata
- fake hashes
- fake encryption metadata
- no real user files or production identifiers

Mark examples clearly as non-functional sample data.

## Security-Sensitive Contributions

If a contribution touches recovery metadata, decryption, wallet signing, key wrapping, package validation, or retrieval verification, describe the security boundary in the pull request. Keep sensitive material out of public discussion and test fixtures.

## Code Of Conduct

A formal code of conduct may be added later. Until then, contributors are expected to be respectful, constructive, and careful with security-sensitive recovery topics.
