# Changelog

Notable changes to dap-ts, following [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

### Added

- Prio3Count reporting for DAP draft 19 and VDAF draft 20, with two aggregators and time-interval batches.
- Task configuration creation and decoding, explicit HPKE key selection, and key rotation.
- Encrypted report preparation, bounded bulk preparation, and partial upload results.
- Transport-neutral upload operations, an optional Fetch adapter, and binary message codecs.
- Specification-vector tests for Prio3Count, TurboSHAKE, and HPKE.
- README with a count-reporting example and usage guidance.
- Source installs and package creation build the distributable JavaScript and declarations.
- Root `Collector` role with authenticated collection requests, resumable polling, HPKE decryption, and exact integer results.
- Root `Leader` and `Helper` roles for explicit, persistable aggregation jobs.

### Changed

- Rename `DAPClient` to `Client` and expose all four roles from the package root. Low-level aggregator and collector modules are no longer package entry points.

### Fixed

- Large upload lists no longer hit JavaScript's function-argument limit during encoding.
- Oversized extension and HPKE configuration lists are rejected before assembling the full message.
