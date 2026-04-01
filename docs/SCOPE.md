# Repository Scope

This repository covers recovery-side consumption of an existing Qave Recovery Package.

It includes the standalone CLI flow to verify, unlock, decrypt, and restore from an existing package.

It does not include producer-side generation of Recovery Packages.

Excluded areas:

* package generation
* exporter / packer
* backend assembly logic
* recovery policy generation
* upload-side / object-lifecycle integration
* producer-side implementation
