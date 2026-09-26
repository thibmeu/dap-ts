# dap-ts

TypeScript reporting client for the [Distributed Aggregation Protocol (DAP)](https://www.ietf.org/archive/id/draft-ietf-ppm-dap-19.txt).
Prepare encrypted measurements for two aggregators and process protocol responses without choosing an HTTP transport.

## Table of contents

- [Example](#example)
- [Usage](#usage)
- [Collection](#collection)
- [Security considerations](#security-considerations)
- [License](#license)

## Example

Use the task configuration agreed with your leader and helper:

```typescript
import { DAPClient, HpkeConfigList, Task, prio3Count } from "dap-ts";

const task = Task.create({
  id: "8BY0RzZMzxvA46_8ymhzycOB9krN-QIGYvg_RsByGec",
  info: "page-views-v1",
  leader: "https://leader.example/",
  helper: "https://helper.example/",
  timePrecision: 60,
  minBatchSize: 100,
  batchMode: "time-interval",
  vdaf: prio3Count(),
});

const hpke = {
  leader: HpkeConfigList.parse(leaderHpkeConfigBytes),
  helper: HpkeConfigList.parse(helperHpkeConfigBytes),
};
const client = new DAPClient(task, { hpke });
const report = await client.prepareReport(1);
const upload = client.prepareUpload([report]);
const response = await fetch(upload.request.url, {
  method: upload.request.method,
  headers: upload.request.headers,
  body: upload.request.body,
});
const result = upload.process({
  status: response.status,
  headers: Object.fromEntries(response.headers),
  body: new Uint8Array(await response.arrayBuffer()),
});

for (const rejection of result.rejected) {
  console.warn(rejection.id, rejection.code);
}
```

## Usage

The package uses ESM and Web APIs. It supports Prio3Count, Prio3Sum, and Prio3Histogram with
time-interval batches, targeting DAP draft 19 and
[VDAF draft 20](https://www.ietf.org/archive/id/draft-irtf-cfrg-vdaf-20.txt).

- `Task.create()` configures a task; `Task.decode()` reads provisioned configuration bytes.
- `prepareReport()` accepts `0` or `1` for count tasks. For sums, use `prio3Sum(maxMeasurement)` and report an integer from `0` through that bound. Sum measurements and bounds can be `bigint`. For histograms, use `prio3Histogram(length, chunkLength)` and report a bucket index from `0` through `length - 1`.
- `prepareUpload()` returns request metadata and a response processor for your own transport.
- `PreparedUpload.request` contains the request to send; `process()` validates the response and reports each outcome.
- `result.accepted` and `result.rejected` describe individual outcomes. Request-level protocol failures throw `DAPError`.

Supply provisioned or retrieved HPKE lists through `HpkeConfigList.parse()`
or rotate keys with `client.withHpkeConfigs()`. Reuse prepared reports when
retrying an uncertain network outcome.

Binary codecs live in `dap-ts/messages`. [Sinbad](https://github.com/thibmeu/sinbad) provides Fetch helpers for HPKE retrieval, upload, and collection polling.

For a bounded sum, set `vdaf: prio3Sum(1337)` when creating the task and call
`client.prepareReport(42)`. Import `prio3Sum` from `dap-ts`. Both aggregators
must be provisioned with the same bound.

For a fixed histogram, set `vdaf: prio3Histogram(4, 2)` and call
`client.prepareReport(2)` to report bucket 2. Import `prio3Histogram` from
`dap-ts`. The length and chunk length must match both aggregators; this package
supports values from 1 through 4096 for each.

## Collection

Collection is a separate backend import. The collector HPKE key and HTTP
credentials must stay on the backend. Both aggregators must have the matching
collector HPKE configuration.

```typescript
import { Collector } from "dap-ts/collector";

const collector = new Collector(task, {
  configId: collectorConfigId,
  privateKey: collectorPrivateKey,
});
const prepared = collector.prepare({ start: batchStart, duration: 1 });
// Send prepared.request with your transport, then pass its status, headers,
// and Uint8Array body to prepared.process(response).
const progress = await prepared.process(collectionResponse);

if (progress.status === "complete") console.log(progress.count); // bigint
else saveForLater(progress.state);
```

When a job is pending, persist `progress.state` and call `collector.resume(state)`
to prepare the next request. The collector supports the DAP 19 Prio3Count,
Prio3Sum, and Prio3Histogram profiles; the Janus DAP 18 upload test does not
exercise collection. For sum tasks, completed progress has `sum` instead of
`count`; both are `bigint`. Histogram tasks return `histogram`, an array of
`bigint` bucket counts.

## Security considerations

This library has not been audited.

## License

[MIT](LICENSE). Specification test vectors retain their [IETF notices](test/vectors/LICENSE).
