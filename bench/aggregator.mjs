import { cpus } from "node:os";
import { performance } from "node:perf_hooks";
import { readFile } from "node:fs/promises";
import { DAPClient, HpkeConfigList, prio3Count, Task } from "../dist/index.js";
import {
	leaderCountJobInit,
	helperCountJobInit,
	prepareAggregatorKey,
} from "../dist/aggregator.js";
import {
	decodeReport,
	encodeHpkeConfigList,
	encodeReport,
} from "../dist/messages.js";

const hpkeVector = JSON.parse(
	await readFile(
		new URL("../test/vectors/hpke-rfc9180-a1.json", import.meta.url),
	),
);
const task = Task.create({
	id: "8BY0RzZMzxvA46_8ymhzycOB9krN-QIGYvg_RsByGec",
	leader: "https://leader.example/",
	helper: "https://helper.example/",
	timePrecision: 60,
	minBatchSize: 100,
	batchMode: "time-interval",
	vdaf: prio3Count(),
});
const config = {
	id: 7,
	kemId: 32,
	kdfId: 1,
	aeadId: 1,
	publicKey: Uint8Array.fromHex(hpkeVector.pkRm),
};
const hpke = {
	leader: HpkeConfigList.parse(encodeHpkeConfigList([config])),
	helper: HpkeConfigList.parse(encodeHpkeConfigList([{ ...config, id: 8 }])),
};
const client = new DAPClient(task, { hpke });
const report = decodeReport(encodeReport(await client.prepareReport(1)));
const leaderKey = {
	configId: 7,
	privateKey: Uint8Array.fromHex(hpkeVector.skRm),
};
const helperKey = {
	configId: 8,
	privateKey: Uint8Array.fromHex(hpkeVector.skRm),
};
const preparedLeaderKey = await prepareAggregatorKey(leaderKey);
const preparedHelperKey = await prepareAggregatorKey(helperKey);
const verifyKey = new Uint8Array(32);
const leader = await leaderCountJobInit(task, report, leaderKey, 0, verifyKey);

async function measure(fn) {
	for (let i = 0; i < 30; i++) await fn();
	if (global.gc) global.gc();
	const beforeMemory = process.memoryUsage();
	const samples = [];
	for (let i = 0; i < 200; i++) {
		const start = performance.now();
		await fn();
		samples.push(performance.now() - start);
	}
	samples.sort((a, b) => a - b);
	if (global.gc) global.gc();
	const afterMemory = process.memoryUsage();
	return {
		p50Ms: samples[100],
		p95Ms: samples[190],
		rssAfterMiB: afterMemory.rss / 2 ** 20,
		retainedHeapDeltaMiB:
			(afterMemory.heapUsed - beforeMemory.heapUsed) / 2 ** 20,
	};
}

console.log(
	JSON.stringify(
		{
			node: process.version,
			platform: `${process.platform}/${process.arch}`,
			cpu: cpus()[0]?.model,
			samples: 200,
			preparedLeader: await measure(() =>
				leaderCountJobInit(task, report, preparedLeaderKey, 0, verifyKey),
			),
			preparedHelper: await measure(() =>
				helperCountJobInit(
					task,
					leader.request,
					preparedHelperKey,
					0,
					verifyKey,
				),
			),
			leader: await measure(() =>
				leaderCountJobInit(task, report, leaderKey, 0, verifyKey),
			),
			helper: await measure(() =>
				helperCountJobInit(task, leader.request, helperKey, 0, verifyKey),
			),
		},
		null,
		2,
	),
);
