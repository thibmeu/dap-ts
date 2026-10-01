# Changelog

Notable changes to @thibmeu/dap, following [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## Unreleased

### Changed

- Process up to four reports concurrently per Leader/Helper job, preserving report order and reusing fixed task and HPKE context bytes.
- Import the collector HPKE public key once per Leader/Helper instead of per aggregate share.
- Speed up Prio3Histogram verification: decode Field128 with two 64-bit reads, cache inverse NTT roots, and evaluate wire polynomials without building the wire matrix.
- Stop copying prepared reports when assembling uploads and request bodies.

### Fixed

- Reject Sum collections whose measurement bound times the report count can wrap modulo Field64.
- Take owned copies of caller bytes. With Node.js Buffers, `slice()` returned views, so wiping or reusing a buffer after the call changed verification keys, the collector key, HPKE config lists, decoded tasks and messages, and joint randomness inputs. `addToBucket()` also ignored a Buffer's byte offset and corrupted the bucket.

## [0.1.0] - 2026-09-30

First release, targeting DAP draft 19 and VDAF draft 20 with two aggregators
and time-interval batches.

### Added

- Prio3Count, Prio3Sum, and Prio3Histogram, checked against the published VDAF vectors.
- `Task` to create or decode a task configuration.
- `Client` to prepare encrypted reports and upload requests, with HPKE key rotation.
- `Collector` to request collections, resume pending jobs, and decrypt results.
- `Leader` and `Helper` for upload intake, aggregation jobs, batch buckets, and aggregate shares. The host owns HTTP, authentication, and storage.
- `DAPError` and `problemResponse()` for RFC 9457 problem details.
- Binary message codecs in `@thibmeu/dap/messages`.

[0.1.0]: https://github.com/thibmeu/dap-ts/releases/tag/v0.1.0
