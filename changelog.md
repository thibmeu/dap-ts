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
- GitHub Actions checks for vectors, types, lint, build, and package contents.
- `DAPError.problem` carries an RFC 9457 problem document from an error response, with `problem.dapError` holding the DAP error token such as `invalidBatchSize`. `parseProblem()` is exported.
- `maxSkewSeconds` configures how far a report timestamp may lead an aggregator's clock. It defaults to 300 seconds as before.
- `Leader.upload()` checks an upload without decrypting it and `respond()` builds the UploadErrors body in request order, including the host's own rejections.
- Batch buckets: `addToBucket()`, `mergeBuckets()`, and `bucketReportCount()` keep the aggregate share, report count, report ID checksum, and report time span in one opaque value.
- `leader.collection()` and `helper.aggregateShare()` validate collection requests and build AggregateShareReq, AggregateShare, and CollectionJobResp. The Helper answers `batchMismatch` on a count or checksum difference and both roles answer `invalidBatchSize` below the minimum.
- Aggregators accept several HPKE keys and verification keys, and serve their HPKE list from `hpkeConfigs`, so keys can rotate as DAP 19, 4.4.1 recommends.
- `DAPError.type` carries the DAP problem type a server should answer with, and `problemResponse()` builds the RFC 9457 response. The Helper now answers `invalidAggregationParameter` and `unsupportedExtension` where the spec names them.
- The security notes describe what the Leader learns from an upload and when an Oblivious HTTP proxy is needed.

### Changed

- Rename `DAPClient` to `Client` and expose all four roles from the package root. Low-level aggregator and collector modules are no longer package entry points.
- Build every role the same way: `await Client.create()`, `await Leader.create()`, `await Helper.create()`, and `await Collector.create()`. Constructors are private. `Client` imports both HPKE public keys when it is created, and `withHpkeConfigs()` returns a Promise.
- `Leader` and `Helper` are classes with exported types. Declarations no longer expose internal module paths, so a host can name an aggregation job, a pending report, or a verified report.
- `helper.verify()` returns per-report results and a `seal()` step instead of a response body that must not be sent until the host has committed. `seal()` checks that the responses still line up with the job.
- VDAF factories return a fresh configuration each call. Tasks compare VDAF configurations structurally, so there is no module-global cache keyed by caller input.
- `Task<V>` is typed by its VDAF. The measurement type follows it (Count takes `0 | 1`), and a completed collection has one `value` typed by the VDAF instead of `count`, `sum`, or `histogram`.
- Client and Collector use Web `Request` and `Response`. `DAPRequest`, `DAPResponse`, and the `parseProblem()` export are gone; `process()` is async.
- Every public time is Unix milliseconds: prepared report times, collection queries (`{ start, end }`), saved collection state, and results. Report counts are numbers.
- Report IDs are URL-safe Base 64 strings and report errors are names in every role. Upload rejections use `error` instead of `code`.
- The Leader persists one `state` value per job and `finish(state, response)` takes it back. `prepare()` takes encoded reports. `helper.verify()` returns each report's outcome, and `seal()` takes the host's rejections by report ID instead of a response list. `helper.reject()` and the Count-only job functions are removed.
- Aggregator options are `hpkeKeys`, `verifyKeys`, `collector`, `maxSkewSeconds`, and `clock`, replacing `hpke`, `verificationKeyId`, `verifyKey`, and per-call `VerifyOptions`.


### Fixed

- Sum and Histogram aggregation and sharding use about half the CPU: the
  shared modular reduction did one BigInt division instead of two, and NTT
  roots of unity and size inverses are no longer recomputed per report.
- Large upload lists no longer hit JavaScript's function-argument limit during encoding.
- Oversized extension and HPKE configuration lists are rejected before assembling the full message.
- Requests use `redirect: "manual"`, which workerd accepts; `"error"` threw there. A redirect still fails the status check.
- ID encoding, integer encoding, and message parsing no longer go through `atob`, `btoa`, or per-byte BigInt arithmetic.
- Recipient key pairs let the aggregator and collector decrypt in workerd while keeping their stored private keys nonextractable.
- Collection job locations follow the Leader's choice of identifier and path, as DAP allows, instead of requiring a 16-byte identifier directly under the collection jobs resource.
