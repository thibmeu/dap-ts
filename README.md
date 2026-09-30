# @thibmeu/dap

[![NPM](https://img.shields.io/npm/v/@thibmeu/dap?style=flat-square)](https://www.npmjs.com/package/@thibmeu/dap)
[![License](https://img.shields.io/npm/l/@thibmeu/dap?style=flat-square)](LICENSE)

TypeScript implementation of the Distributed Aggregation Protocol (DAP), as specified in [draft-ietf-ppm-dap-19](https://www.ietf.org/archive/id/draft-ietf-ppm-dap-19.html).
Clients encrypt measurements, two aggregators verify and sum them without
seeing any single value, and a collector gets only the aggregate.

## Features

- **[DAP draft 19](https://www.ietf.org/archive/id/draft-ietf-ppm-dap-19.html)**: all four roles: Client, Leader, Helper, and Collector
- **[VDAF draft 20](https://www.ietf.org/archive/id/draft-irtf-cfrg-vdaf-20.html)**: Prio3Count, Prio3Sum, and Prio3Histogram, checked against the published vectors
- **Web APIs**: runs in browsers, Web Workers, Cloudflare Workers, and Node.js
- **Bring your own I/O**: Client and Collector build Web `Request` objects and read `Response` objects; aggregators take and return bytes. HTTP, authentication, and storage stay with you

## Installation

```bash
npm install @thibmeu/dap
```

## Quick start

Create a task with the configuration agreed with your Leader and Helper, then
report a measurement:

```typescript
import { Client, HpkeConfigList, Task, prio3Count } from "@thibmeu/dap";

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

const client = await Client.create(task, {
  hpke: {
    leader: HpkeConfigList.parse(leaderHpkeConfigBytes),
    helper: HpkeConfigList.parse(helperHpkeConfigBytes),
  },
});
const report = await client.prepareReport(1);
const upload = client.prepareUpload([report]);
const result = await upload.process(await fetch(upload.request));

for (const { id, error } of result.rejected) console.warn(id, error);
```

`task.encodeConfiguration()` and `Task.decode({ id, configuration })` move a
task between services.
`prio3Sum(max)` takes an integer from 0 to `max`, as a number or `bigint`.
`prio3Histogram(length, chunkLength)` takes a bucket index below `length`, up
to 4096 buckets.

Times are Unix milliseconds and report IDs are URL-safe Base64. Retry an
uncertain upload with the same prepared report so the aggregators can drop the
duplicate. Rotate aggregator keys with `await client.withHpkeConfigs(hpke)`.
Binary message codecs are in `@thibmeu/dap/messages`.

## Collection

The Collector runs on a backend. Keep its HPKE private key and HTTP credentials
there.

```typescript
import { Collector } from "@thibmeu/dap";

const collector = await Collector.create(task, {
  configId: collectorConfigId,
  privateKey: collectorPrivateKey,
});
const day = Date.UTC(2026, 8, 28);
const prepared = collector.prepare({ start: day, end: day + 86_400_000 });
const request = prepared.request;
request.headers.set("authorization", `Bearer ${collectorToken}`);
const progress = await prepared.process(await fetch(request));

if (progress.status === "complete") console.log(progress.value); // 123n
else saveForLater(progress.state);
```

The interval must fall on the task's time precision. A pending job's
`progress.state` is plain JSON; `collector.resume(state)` prepares the next
poll. The result is a `bigint` for Count and Sum and a `bigint[]` for
Histogram.

## Aggregators

`Leader` and `Helper` run the DAP protocol steps on bytes. Your server
routes HTTP, authenticates peers, and stores reports, jobs, and batch buckets.

```typescript
import { Helper, Leader } from "@thibmeu/dap";

const leader = await Leader.create(task, {
  hpkeKeys: [{ configId: 1, privateKey: leaderHpkeKey }],
  verifyKeys: [{ id: 0, key: verifyKey }],
  collector: collectorHpkeConfig,
});
const helper = await Helper.create(task, {
  hpkeKeys: [{ configId: 1, privateKey: helperHpkeKey }],
  verifyKeys: [{ id: 0, key: verifyKey }],
  collector: collectorHpkeConfig,
});

// Leader, on upload: store accepted reports and answer with the rejections.
const incoming = leader.upload(body);
const replayed = incoming.reports.filter(seenBefore);
store(incoming.reports.filter((r) => !seenBefore(r)));
reply(incoming.respond(replayed.map(({ id }) => ({ id, error: "report-replayed" }))));

// Leader, later: build a job. Persist request and state before sending.
const job = await leader.prepare(storedReports);

if (job.request) {
  // Helper: verify, commit the output shares, then seal the response.
  const verified = await helper.verify(job.request);
  for (const r of verified.reports)
    if (r.outputShare) updateBucket(r.time, (b) => helper.addToBucket(b, r));
  const response = verified.seal();

  // Leader: finish from the saved state and commit each output share once.
  for (const r of leader.finish(job.state, response))
    if (r.outputShare) updateBucket(r.time, (b) => leader.addToBucket(b, r));
}
```

A batch bucket is one opaque `Uint8Array` per report time; pass `undefined`
to start one. For collection, `leader.collection(body)` and
`helper.aggregateShare(body)` return the requested interval. Merge its buckets
with `mergeBuckets()`, then call the returned job's `finish()`.

Your storage must enforce what the library cannot see: reject replayed reports
and reports for collected batches, commit output shares together with the
response bytes, answer retries from those bytes, and keep batches with pending
jobs out of collection.

Serve each role's HPKE list from `role.hpkeConfigs`. List keys most preferred
first and keep a retired key for twice the configuration's cache lifetime.

## Errors

Request-level failures throw `DAPError`. When a peer answers with an
RFC 9457 problem document, `error.problem.dapError` holds its DAP error type,
such as `invalidBatchSize`. On a server, `problemResponse(error, task.id)`
turns an error into that response and hides errors this library did not raise.

## Security considerations

**Not audited.** Use at your own risk.

Correctness is tested against the published VDAF and HPKE vectors, with
hand-derived DAP message fixtures and malformed-input tests.

DAP protects measurements only while the Leader and Helper do not collude. It
does not add differential privacy, and a small batch can reveal individual
values: set `minBatchSize` accordingly.

DAP hides what a client reported, not that it reported. The Leader sees each
upload's source IP, arrival time, and task ID ([draft-ietf-ppm-dap-19, Section 8](https://www.ietf.org/archive/id/draft-ietf-ppm-dap-19.html#section-8)). If that is
sensitive, send reports through an Oblivious HTTP relay ([Section 8.4](https://www.ietf.org/archive/id/draft-ietf-ppm-dap-19.html#section-8.4)) or
report on a fixed schedule.

## License

[MIT](LICENSE). Specification test vectors keep their [IETF notices](test/vectors/LICENSE).
