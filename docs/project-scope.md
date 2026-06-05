# Project Scope

Qave Recovery Toolkit is intended as a public-good recovery toolkit baseline for encrypted Filecoin-backed data. The grant-funded work is the open-source recovery toolkit, not Qave's commercial product.

## Grant-Funded Open-Source Scope

The grant-funded scope includes:

- Recovery Package Manifest v1 documentation
- recovery package examples using non-sensitive placeholder data
- recovery CLI hardening
- retrieval verification workflow
- local verification and decryption workflow documentation
- browser-based recovery tool workflow
- Qave reference implementation documentation
- independent recovery drill plan and public report
- user and developer documentation

The scope is application-independent. Qave is the first reference implementation, but the manifest and recovery concepts should be understandable by other Filecoin-backed applications.

## Qave Commercial Application Boundary

Qave's normal commercial application is out of scope for the grant except where it demonstrates the recovery toolkit as a reference implementation.

Out-of-scope areas include:

- billing and subscription behavior
- commercial product features
- internal dashboards
- private operations workflows
- production deployment details
- private URLs, credentials, API keys, or secrets
- closed-source commercial Qave details

## What Will Be Open Source

The public toolkit baseline is expected to include:

- manifest and package documentation
- recovery assumptions and limitations
- recovery CLI source and tests
- browser recovery tool source
- retrieval verification and integrity documentation
- non-sensitive examples
- recovery drill documentation
- Qave reference implementation notes

## What Is Not Grant-Funded

The grant does not fund:

- Qave's commercial app roadmap
- production hosting or operations
- subscription or payment systems
- private customer support tooling
- proprietary Qave business logic

## Qave As First Reference Implementation

Qave is the first application-layer reference context for the recovery package workflow. The grant-funded work will document and harden how an encrypted Filecoin-backed application can export recovery metadata and how a user can attempt recovery with required user-held materials when the encrypted data remains retrievable.

The recovery workflow is designed to work without relying on the normal Qave frontend/backend API, while still requiring Filecoin/IPFS retrieval paths, gateways, or providers and retained user recovery materials.

This reference implementation should not be read as a requirement that other applications copy Qave-specific product architecture.
