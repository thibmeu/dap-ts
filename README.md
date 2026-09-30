# dap-ts

TypeScript implementation of the [Distributed Aggregation Protocol (DAP)](https://www.ietf.org/archive/id/draft-ietf-ppm-dap-19.txt).
Report encrypted measurements, run the Leader and Helper protocol steps, and collect results, with Web `Request` and `Response` objects and storage left to you.

## Table of contents

- [Example](#example)
- [Usage](#usage)
- [Collection](#collection)
- [Aggregators](#aggregators)
- [Security considerations](#security-considerations)
- [License](#license)

## Example

Use the task configuration agreed with your leader and helper:

```typescript
import { Client, HpkeConfigList, Task, prio3Count } from "dap-ts";

const task = Task.create({
  id: "8BY0RzZMzxvA46_8ymhzycOB9krN-QIGYvg_RsByGec",
  info: "page-views-v1",
  leader: "https://leader.example/",
  helper: "https://helper.example/",
  timePrecision: 3600,
  minBatchSize: 100,
  batchMode: "time-interval",
  vdaf: prio3Count(),
});

const hpke = {
  leader: HpkeConfigList.parse(leaderHpkeConfigBytes),
  helper: HpkeConfigList.parse(helperHpkeConfigBytes),
};
const client = await Client.create(task, { hpke });
const report = await client.prepareReport(1);
const upload = client.prepareUpload([report]);
const result = await upload.process(await fetch(upload.request));

for (const rejection of result.rejected) {
  console.warn(rejection.id, rejection.error);
}
```

## Usage

The package uses ESM and Web APIs. It supports Prio3Count, Prio3Sum, and Prio3Histogram with
time-interval batches, targeting DAP draft 19 and
[VDAF draft 20](https://www.ietf.org/archive/id/draft-irtf-cfrg-vdaf-20.txt).
The packed package has been smoke-tested on Node 26, headless Chrome and
Firefox, and a Chrome Dedicated Worker. A local `workerd` run covered reporting,
aggregation, and Count collection. The browser aggregation checks used a
restrictive content security policy. Mobile browsers and a deployed Cloudflare
Worker have not been tested.

- `Task.create()` configures a task; `Task.decode()` reads provisioned configuration bytes and `task.expect(vdaf)` narrows its type.
- The VDAF fixes the measurement type. `prio3Count()` takes `0` or `1`. `prio3Sum(maxMeasurement)` takes an integer from `0` through the bound, as a number or `bigint`. `prio3Histogram(length, chunkLength)` takes a bucket index from `0` through `length - 1`; this package supports lengths and chunk lengths from 1 through 4096.
- All four roles are built the same way: `await Client.create()`, `await Leader.create()`, `await Helper.create()`, `await Collector.create()`. Each imports its key material once.
- Client and Collector requests are Web `Request` objects, read afresh each time you access `.request`, and `process()` takes the `Response`. Add authentication headers with `request.headers.set()`.
- Times are Unix milliseconds throughout. Report IDs are URL-safe Base 64 strings. Report errors are names such as `report-replayed`, matching DAP's registry.
- `result.accepted` and `result.rejected` describe individual outcomes. Request-level protocol failures throw `DAPError`. When a peer returns an RFC 9457 problem document, `error.problem.dapError` holds the registered token, such as `invalidBatchSize`, so a caller can retry or give up without parsing the body.

Supply provisioned or retrieved HPKE lists through `HpkeConfigList.parse()`
or rotate keys with `await client.withHpkeConfigs()`. Reuse prepared reports when
retrying an uncertain network outcome.

Binary codecs live in `dap-ts/messages`. [Sinbad](https://github.com/thibmeu/sinbad) provides Fetch helpers for HPKE retrieval, upload, and collection polling.

## Collection

Collection uses the backend-only Collector role. The collector HPKE key and HTTP
credentials must stay on the backend. Both aggregators must have the matching
collector HPKE configuration.

```typescript
import { Collector } from "dap-ts";

const collector = await Collector.create(task, {
  configId: collectorConfigId,
  privateKey: collectorPrivateKey,
});
const day = Date.UTC(2026, 8, 28);
const prepared = collector.prepare({ start: day, end: day + 86_400_000 });
const request = prepared.request;
request.headers.set("authorization", `Bearer ${collectorToken}`);
const progress = await prepared.process(await fetch(request));

if (progress.status === "complete") console.log(progress.value); // bigint
else saveForLater(progress.state);
```

Both ends of the interval must fall on the task's time precision. A batch
spans every bucket in the interval, so one query can cover a day of hourly
buckets. When a job is pending, persist `progress.state` (plain JSON) and call
`collector.resume(state)` to prepare the next request. `progress.value` is a
`bigint` for Count and Sum and an array of `bigint` bucket counts for
Histogram. The Janus DAP 18 upload test does not exercise collection.

## Aggregators

`Leader` and `Helper` implement the DAP 19 protocol steps; the host supplies
HTTP, authentication, scheduling, and storage. Each role takes every HPKE key
it accepts, most preferred first, and serves the matching list from
`role.hpkeConfigs`. Keep a retired key for twice the configuration's cache
lifetime. The Leader starts jobs with the first verification key and the
Helper accepts any listed ID.

```typescript
import { Helper, Leader, problemResponse } from "dap-ts";

const options = {
  hpkeKeys: [{ configId: 1, privateKey }],
  verifyKeys: [{ id: 0, key: verifyKey }],
  collector: collectorHpkeConfig,
};
const leader = await Leader.create(task, options);
const helper = await Helper.create(task, { ...options, hpkeKeys: helperKeys });

// Leader, on upload: store accepted reports, answer with the error list.
const upload = leader.upload(body);
const refused = upload.reports.filter(seenBefore).map(({ id }) => ({ id, error: "report-replayed" }));
store(upload.reports.filter((report) => !seenBefore(report)));
reply(upload.respond(refused));

// Leader, later: one job over stored reports. Save request and state first.
const job = await leader.prepare(storedReports.map((r) => r.report));
if (job.request) {
  // Helper: verify, commit accepted shares, then seal and cache the response.
  const verified = await helper.verify(job.request);
  for (const report of verified.reports)
    if (report.outputShare)
      bucket(report.time, (b) => helper.addToBucket(b, report));
  const response = verified.seal(helperRefused);

  // Leader: finish from saved state and commit each share once.
  for (const report of leader.finish(job.state, response))
    if (report.outputShare)
      bucket(report.time, (b) => leader.addToBucket(b, report));
}
```

A batch bucket is one opaque `Uint8Array` per task and report `time`. It
holds the aggregate share, report count, checksum, and the span of report
times. `addToBucket(undefined, report)` starts one.

Collection runs on both roles the same way: `leader.collection(body)` or
`helper.aggregateShare(body)` validates the request and returns its
`interval`. The host merges that interval's buckets with `mergeBuckets()`,
then `aggregateShareRequest()` and `finish()` build the messages. The Helper
fails with `batchMismatch` if its count or checksum differs from the Leader's,
and both refuse batches below the minimum size with `invalidBatchSize`.

Failures carry the spec's problem type in `error.type`.
`problemResponse(error, task.id)` turns any error into an RFC 9457 response
and hides errors this library did not raise.

The host still owns the rules that need storage: check replay and collected
buckets before a report joins a job, commit shares and cache response bytes
atomically, return cached bytes on retry, and keep buckets with pending Leader
jobs out of collection.

`npm run bench:aggregator` measures the local verifier path for one job on
Node: prepare, verify and seal, finish, and bucket commits. It excludes HTTP
and storage.

## Security considerations

This library has not been audited.
DAP requires independent aggregators and suitable batch policies. It does not
provide differential privacy or prevent disclosure from very small batches.

DAP protects measurement contents, not the fact that a client reported. The
Leader still sees each upload's source IP, arrival time, and task ID, and can
use them to profile clients (DAP 19, Section 8). If reporting itself is
sensitive, or if a task ID distinguishes what the user did, send reports
through an anonymizing proxy using Oblivious HTTP (Section 8.4), report on a
fixed schedule regardless of the measurement, or both. Report timestamps are
already truncated to the task's time precision.

## License

[MIT](LICENSE). Specification test vectors retain their [IETF notices](test/vectors/LICENSE).
