import { cpus } from "node:os";
import { performance } from "node:perf_hooks";

const start = performance.now();
const { shardCountWithRandomness } = await import("../dist/prio3-count.js");
const importMs = performance.now() - start;
const ctx = new TextEncoder().encode("dap-19 benchmark");
const nonce = new Uint8Array(16);
const shard = (measurement: number) =>
	shardCountWithRandomness(
		measurement,
		ctx,
		nonce,
		crypto.getRandomValues(new Uint8Array(64)),
	);

// Measures local sharding, including its randomness. HPKE and HTTP are absent.
for (let i = 0; i < 100; i++) shard(1);
const samples: number[] = [];
for (let i = 0; i < 1000; i++) {
	const before = performance.now();
	shard(i % 2);
	samples.push(performance.now() - before);
}
samples.sort((a, b) => a - b);
console.log(
	JSON.stringify(
		{
			node: process.version,
			platform: `${process.platform}/${process.arch}`,
			cpu: cpus()[0]?.model,
			samples: samples.length,
			importMs,
			p50Ms: samples[500],
			p95Ms: samples[950],
			shareBytes: { public: 0, leader: 48, helper: 32 },
		},
		null,
		2,
	),
);
