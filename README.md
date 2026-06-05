# Qave Recovery Toolkit / qave-recovery-cli

Qave Recovery Toolkit / qave-recovery-cli is an early open-source baseline for application-independent recovery of encrypted Filecoin-backed data. It defines recovery package concepts, verification documentation, CLI and browser recovery tooling, and example package structures for recovery workflows designed to work without relying on the normal Qave frontend/backend API, while still requiring Filecoin/IPFS retrieval paths, gateways, or providers and retained user recovery materials.

Current status: a Filecoin ProPGF Batch 3 grant application has been submitted, and this repository is being prepared as an early public-facing baseline. The toolkit is not a guarantee of successful recovery. Recovery requires retrievable encrypted data and the user retaining the required recovery package and recovery materials.

## Why This Matters

Filecoin-backed applications can store encrypted user data in durable decentralized storage, but users often still depend on an application frontend, backend, account system, or product-specific export path to retrieve and decrypt that data. If the normal application path is unavailable, users need a documented and auditable recovery path that is designed to work without relying on the normal Qave frontend/backend API, while still requiring Filecoin/IPFS retrieval paths, gateways, or providers and retained user recovery materials.

The toolkit addresses that gap by separating recovery materials, retrieval metadata, verification steps, and local decryption workflows from the normal Qave product experience.

## What The Toolkit Solves

The project is intended to help users and ecosystem reviewers answer practical recovery questions:

- What encrypted data needs to be retrieved?
- Which content identifiers, provider hints, or deal hints are available?
- What recovery materials must the user retain?
- How can a recovery tool verify package integrity before attempting decryption?
- How can recovery proceed when the normal Qave frontend or backend API is unavailable?
- How can another Filecoin-backed application structure a similar recovery package?

The recovery assumption is always explicit: recovery requires the encrypted data to remain retrievable and the user to retain the required recovery materials. If data is no longer retrievable, or if required user-held recovery material is lost, this toolkit cannot guarantee restoration.

## Current Public Baseline

The current public baseline includes:

- recovery package and manifest documentation
- recovery assumptions and limitation documentation
- non-sensitive sample recovery package structures
- an independent recovery drill plan
- public roadmap, contribution, and security guidance

## Planned Grant Deliverables

Planned grant deliverables include:

- Recovery Package Manifest v1 hardening
- recovery CLI hardening
- retrieval verification workflows
- browser-based recovery tool
- Qave reference implementation documentation
- public demo and final report
- non-Qave integration example

## Not Included

The toolkit does not include:

- Qave commercial product scope, billing, subscription, or internal operations logic
- production deployment details, private URLs, internal dashboards, secrets, or API keys
- a promise that every recovery scenario will succeed
- new recovery logic beyond what is already present in the repository
- custody of user private keys, wallet seed phrases, or recovery keys

## Relationship To Qave

Qave is the first application-layer reference context for this toolkit. The grant-funded work will document and harden how an encrypted Filecoin-backed application can export recovery metadata and how a user can attempt recovery with required user-held materials when the encrypted data remains retrievable.

The grant-funded public-good boundary is the recovery toolkit: package formats, recovery tooling, documentation, examples, verification workflows, and repeatable recovery drills. Qave's commercial application remains out of scope except where it serves as the initial reference implementation.

## Planned Milestones

Milestone 1: Recovery Package Manifest v1 and open-source baseline

- public README, roadmap, contribution guide, security policy, and scope documentation
- draft Recovery Package Manifest v1
- non-sensitive Qave and non-Qave example recovery package structures
- repository cleanup around the public-good boundary

Milestone 2: Hardened Recovery CLI and retrieval verification workflow

- manifest parsing
- local decryption flow hardening
- integrity verification
- recovery logs
- retrieval verification workflow
- demo scripts

Milestone 3: Browser-based Recovery Tool and Qave reference implementation

- browser recovery package import
- recovery material input
- local verification and decryption
- restored file download
- Qave reference implementation documentation

Milestone 4: Independent recovery drill, public demo, docs, final report

- recovery drill with the normal Qave frontend/backend API unavailable
- public demo
- user and developer documentation
- external review or ecosystem participant feedback
- final report
- non-Qave integration example

See [ROADMAP.md](ROADMAP.md) for the four-month roadmap.

## Recovery Assumptions And Limitations

Recovery depends on all of the following:

- the encrypted data remains retrievable from Filecoin/IPFS retrieval paths, gateways, or providers
- the user has the required recovery package or manifest
- the user retains required recovery materials, such as the matching wallet account and recovery key for Qave packages
- the recovery package has enough metadata to identify, verify, and decrypt the intended files

The recovery workflow is designed to work without relying on the normal Qave frontend/backend API, while still requiring Filecoin/IPFS retrieval paths, gateways, or providers and retained user recovery materials. See [docs/recovery-assumptions.md](docs/recovery-assumptions.md).

## Repository Structure

- [main.go](main.go) and related root Go files - current Qave recovery CLI source and tests
- [tools/qave-recovery-tool-v1](tools/qave-recovery-tool-v1) - browser recovery tool prototype
- [docs/RECOVERY_GUIDE.md](docs/RECOVERY_GUIDE.md) - existing Qave recovery CLI user guide
- [docs/manifest-v1.md](docs/manifest-v1.md) - draft application-independent manifest skeleton
- [docs/project-scope.md](docs/project-scope.md) - grant-funded public-good scope boundary
- [docs/recovery-drill-plan.md](docs/recovery-drill-plan.md) - independent recovery drill plan
- [docs/SCOPE.md](docs/SCOPE.md) - current repository implementation scope note
- [docs/TRADEMARKS.md](docs/TRADEMARKS.md) - trademark boundary note
- [examples/qave](examples/qave) - non-sensitive Qave reference sample package
- [examples/non-qave](examples/non-qave) - non-Qave sample package structure

## Development

Recovery CLI:

```bash
go test ./...
```

Browser recovery tool core tests:

```bash
node --test tools/qave-recovery-tool-v1/core.test.mjs
```

## License Status

This repository includes a GPLv3 license in [LICENSE](LICENSE). Code license terms and trademark permissions are separate; see [docs/TRADEMARKS.md](docs/TRADEMARKS.md).
