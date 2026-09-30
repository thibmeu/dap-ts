import { readFile } from "node:fs/promises";
import { cpus } from "node:os";
import { performance } from "node:perf_hooks";
import {
	Client,
	Helper,
	HpkeConfigList,
	Leader,
	prio3Count,
	prio3Histogram,
	prio3Sum,
	Task,
	type Vdaf,
} from "../dist/index.js";
import { encodeHpkeConfigList, encodeReport } from "../dist/messages.js";

// Measures the local verifier path for one job of `batch` reports: Leader
// prepare, Helper verify and seal, Leader finish, and committing the shares
// to a bucket. HTTP and storage are excluded.
const vector = JSON.parse(
	await readFile(
		new URL("../test/vectors/hpke-rfc9180-a1.json", import.meta.url),
		"utf8",
	),
) as { skRm: string; pkRm: string };
const privateKey = Uint8Array.fromHex(vector.skRm);
const suite = {
	kemId: 32,
	kdfId: 1,
	aeadId: 1,
	publicKey: Uint8Array.fromHex(vector.pkRm),
};
const hpke = {
	leader: HpkeConfigList.parse(encodeHpkeConfigList([{ ...suite, id: 7 }])),
	helper: HpkeConfigList.parse(encodeHpkeConfigList([{ ...suite, id: 8 }])),
};
const verifyKeys = [{ id: 0, key: new Uint8Array(32) }];
const batch = Number(process.argv[2] ?? 10);

async function measure(fn: () => unknown, samples: number) {
	for (let i = 0; i < 5; i++) await fn();
	const cpu = process.cpuUsage();
	const start = performance.now();
	for (let i = 0; i < samples; i++) await fn();
	const used = process.cpuUsage(cpu);
	return {
		cpuUsPerOp: Math.round((used.user + used.system) / samples),
		wallMsPerOp: +((performance.now() - start) / samples).toFixed(3),
	};
}

const results: Record<string, unknown> = {};
for (const [name, vdaf, measurement] of [
	["count", prio3Count(), 1],
	["sum", prio3Sum(1337), 42],
	["histogram", prio3Histogram(100, 10), 2],
] as [string, Vdaf, number][]) {
	const task = Task.create({
		id: "8BY0RzZMzxvA46_8ymhzycOB9krN-QIGYvg_RsByGec",
		leader: "https://leader.example/",
		helper: "https://helper.example/",
		timePrecision: 60,
		minBatchSize: 1,
		batchMode: "time-interval",
		vdaf,
	});
	const client = await Client.create(task, { hpke });
	const reports = (
		await client.prepareReports(Array(batch).fill(measurement))
	).map(encodeReport);
	const leader = await Leader.create(task, {
		hpkeKeys: [{ configId: 7, privateKey }],
		verifyKeys,
	});
	const helper = await Helper.create(task, {
		hpkeKeys: [{ configId: 8, privateKey }],
		verifyKeys,
	});
	const job = await leader.prepare(reports);
	const request = job.request;
	if (!request) throw new Error("Every report was rejected");
	const response = (await helper.verify(request)).seal();
	const finished = leader.finish(job.state, response);
	const samples = name === "histogram" ? 10 : 40;
	results[name] = {
		leaderPrepare: await measure(() => leader.prepare(reports), samples),
		helperVerifySeal: await measure(
			async () => (await helper.verify(request)).seal(),
			samples,
		),
		leaderFinish: await measure(
			() => leader.finish(job.state, response),
			samples,
		),
		commitBatch: await measure(() => {
			let bucket: Uint8Array | undefined;
			for (const report of finished)
				if (report.outputShare) bucket = leader.addToBucket(bucket, report);
		}, samples * 10),
		bytes: {
			request: request.length,
			response: response.length,
			state: job.state.length,
		},
	};
}

console.log(
	JSON.stringify(
		{ node: process.version, cpu: cpus()[0]?.model, batch, results },
		null,
		2,
	),
);
