# dap-ts

TypeScript reporting client for the [Distributed Aggregation Protocol (DAP)](https://www.ietf.org/archive/id/draft-ietf-ppm-dap-19.txt).
Prepare encrypted measurements for two aggregators, with explicit key configuration and an optional Fetch adapter.

## Table of contents

- [Example](#example)
- [Usage](#usage)
- [Collection](#collection)
- [Security considerations](#security-considerations)
- [License](#license)

## Example

Use the task configuration agreed with your leader and helper:

```typescript
import { DAPClient, Task, prio3Count } from "dap-ts";
import { execute, fetchHpkeConfigs } from "dap-ts/fetch";

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

const hpke = await fetchHpkeConfigs(task);
const client = new DAPClient(task, { hpke });
const report = await client.prepareReport(1);
const result = await execute(client.prepareUpload([report]));

for (const rejection of result.rejected) {
  console.warn(rejection.id, rejection.code);
}
```

## Usage

The package uses ESM and Web APIs. It supports Prio3Count and Prio3Sum with
time-interval batches, targeting DAP draft 19 and
[VDAF draft 20](https://www.ietf.org/archive/id/draft-irtf-cfrg-vdaf-20.txt).

- `Task.create()` configures a task; `Task.decode()` reads provisioned configuration bytes.
- `prepareReport()` accepts `0` or `1` for count tasks. For sums, use `prio3Sum(maxMeasurement)` and report an integer from `0` through that bound. Sum measurements and bounds can be `bigint`.
- `prepareUpload()` returns request metadata and a response processor for your own transport.
- `execute()` sends a prepared upload once. Its options accept custom `fetch`, authentication `headers`, and an abort `signal`.
- `result.accepted` and `result.rejected` describe individual outcomes. Request-level protocol failures throw `DAPError`.

HPKE retrieval is explicit. Supply cached lists through `HpkeConfigList.parse()`
or rotate keys with `client.withHpkeConfigs()`. Reuse prepared reports when
retrying an uncertain network outcome.

Binary codecs live in `dap-ts/messages`; Fetch helpers live in `dap-ts/fetch`.

For a bounded sum, set `vdaf: prio3Sum(1337)` when creating the task and call
`client.prepareReport(42)`. Import `prio3Sum` from `dap-ts`. Both aggregators
must be provisioned with the same bound.

## Collection

Collection is a separate backend import. The collector HPKE key and HTTP
credentials must stay on the backend. Both aggregators must have the matching
collector HPKE configuration.

```typescript
import { Collector } from "dap-ts/collector";
import { collect } from "dap-ts/collector/fetch";

const collector = new Collector(task, {
  configId: collectorConfigId,
  privateKey: collectorPrivateKey,
});
const progress = await collect(
  collector,
  { start: batchStart, duration: 1 }, // DAP time-precision units
  { headers: { authorization: `Bearer ${collectorToken}` } },
);

if (progress.status === "complete") console.log(progress.count); // bigint
else saveForLater(progress.state);
```

`collect()` polls up to 20 times by default and returns resumable state if the
job is still pending or the server asks it to wait more than one minute. Pass
that state to `collect()` later. The collector
supports the DAP 19 Prio3Count and Prio3Sum profiles; the Janus DAP 18 upload test does not
exercise collection.
For sum tasks, completed progress has `sum` instead of `count`; both are `bigint`.

## Security considerations

This library has not been audited.

## License

[MIT](LICENSE). Specification test vectors retain their [IETF notices](test/vectors/LICENSE).
