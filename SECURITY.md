# Security Policy

Qave Recovery Toolkit handles recovery metadata, package verification, retrieval workflows, and local decryption flows. Treat all real recovery materials as sensitive.

## Do Not Share Sensitive Material Publicly

Do not submit any of the following in public issues, pull requests, examples, logs, screenshots, or discussions:

- private keys
- wallet seed phrases
- recovery keys
- real recovery packages
- customer data
- private provider details
- production credentials
- API keys
- private URLs or internal service endpoints

Use placeholder data in examples and test cases.

## Reporting Security Concerns

For suspected vulnerabilities, use GitHub private vulnerability reporting if it is enabled for this repository. If private vulnerability reporting is not available, contact the maintainers through a private channel before posting details publicly.

If you must open a public issue because no private channel is available, include only a high-level description of the affected area and omit exploit details, sensitive logs, real recovery packages, keys, credentials, and private URLs.

## Recovery Limitations

This project does not guarantee recovery in every scenario. Recovery requires:

- encrypted data to remain retrievable
- the user to retain the required recovery package or manifest
- the user to retain required recovery materials
- recovery tooling to support the package version and encryption metadata

If data is no longer retrievable, or if required recovery materials are lost, the toolkit may be unable to restore files.

## Local Decryption Principle

Recovery workflows should prefer local verification and decryption. Sensitive recovery material should not be sent to Qave services, public gateways, analytics systems, or logging systems as part of normal recovery.

When adding logs or diagnostics, avoid recording secrets, recovery keys, wallet signatures, decrypted filenames when unnecessary, plaintext file contents, or production retrieval credentials.
