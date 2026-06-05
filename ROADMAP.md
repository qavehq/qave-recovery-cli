# Roadmap

This roadmap reflects the planned four-month public-good baseline for Qave Recovery Toolkit. The scope is application-independent recovery for encrypted Filecoin-backed data, with Qave as the first reference implementation.

Recovery remains conditional: encrypted data must be retrievable, and the user must retain the required recovery package and recovery materials.

## Month 1: Recovery Package Manifest v1 And Baseline

- Draft Recovery Package Manifest v1.
- Clean up repository documentation around the public-good boundary.
- Add README, roadmap, license status, and contribution guide.
- Add security guidance for recovery metadata and decryption workflows.
- Add a non-sensitive Qave example recovery package.
- Add a non-Qave sample recovery package structure.
- Document recovery assumptions and limitations.

## Month 2: CLI Hardening And Retrieval Verification

- Harden the recovery CLI around manifest parsing.
- Validate local decryption flow behavior and failure modes.
- Add or refine integrity verification steps.
- Improve recovery logs for user-visible troubleshooting without exposing secrets.
- Define retrieval verification workflow for encrypted Filecoin-backed data.
- Add demo scripts for repeatable recovery checks.

## Month 3: Browser Recovery Tool And Reference Docs

- Build browser-based recovery tool workflow.
- Support recovery package import.
- Support recovery material input without sending sensitive material to Qave services.
- Perform local verification and decryption in the browser workflow where appropriate.
- Support restored file download.
- Document the Qave reference implementation and its boundaries.

## Month 4: Independent Drill, Demo, And Final Report

- Run an independent recovery drill with Qave normal frontend/backend API unavailable.
- Publish a public demo.
- Write user documentation.
- Write developer documentation.
- Collect external review or ecosystem participant feedback.
- Publish final report.
- Add or document a non-Qave integration example.
