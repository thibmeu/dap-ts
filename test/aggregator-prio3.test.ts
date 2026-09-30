import { expect, it } from "vitest";
import {
	helperPrio3Init,
	leaderPrio3Finish,
	leaderPrio3Init,
} from "../src/aggregator.js";
import {
	histogramVerifierMessage,
	histogramVerifierShare,
	sumVerifierMessage,
	sumVerifierShare,
} from "../src/aggregator-prio3.js";
import { concat, uint } from "../src/binary.js";
import { Client, Collector, Helper, Leader, Task } from "../src/index.js";
import { encodeReport } from "../src/messages.js";
import { prio3Histogram, prio3Sum } from "../src/vdaf.js";
import {
	collectorKeys,
	deterministicRandom,
	hpke,
	taskOptions,
} from "./fixtures.js";
import hpkeVector from "./vectors/hpke-rfc9180-a1.json";
import histogram0 from "./vectors/Prio3Histogram_0.json";
import histogram2 from "./vectors/Prio3Histogram_2.json";
import badHelperBlind from "./vectors/Prio3Histogram_bad_helper_jr_blind.json";
import badLeaderBlind from "./vectors/Prio3Histogram_bad_leader_jr_blind.json";
import badPublicShare from "./vectors/Prio3Histogram_bad_public_share.json";
import badVerifierMessage from "./vectors/Prio3Histogram_bad_verifier_message.json";
import sum0 from "./vectors/Prio3Sum_0.json";
import sum2 from "./vectors/Prio3Sum_2.json";

const bytes = (hex: string) => Uint8Array.fromHex(hex);

for (const [name, vector] of Object.entries({ sum0, sum2 })) {
	it(`${name}: verifies published Sum shares and output`, () => {
		for (const report of vector.reports) {
			const shares = [0, 1].map((id) =>
				sumVerifierShare(
					id as 0 | 1,
					BigInt(vector.max_measurement),
					bytes(vector.verify_key),
					bytes(vector.ctx),
					bytes(report.nonce),
					bytes(report.public_share),
					bytes(report.input_shares[id]!),
				),
			);
			expect(shares.map((share) => share.verifierShare)).toEqual(
				report.verifier_shares[0]!.map(bytes),
			);
			expect(
				sumVerifierMessage(shares[0]!.verifierShare, shares[1]!.verifierShare),
			).toEqual(bytes(report.verifier_messages[0]!));
			expect(shares.map((share) => share.outputShare)).toEqual(
				report.out_shares.map(bytes),
			);
		}
	});
}

it("rejects a changed Sum proof and non-canonical input share", () => {
	const vector = sum0;
	const report = vector.reports[0]!;
	const args = [
		BigInt(vector.max_measurement),
		bytes(vector.verify_key),
		bytes(vector.ctx),
		bytes(report.nonce),
		bytes(report.public_share),
	] as const;
	const leaderInput = bytes(report.input_shares[0]!);
	const helper = sumVerifierShare(1, ...args, bytes(report.input_shares[1]!));
	leaderInput[(8 + 3) * 8]! ^= 1;
	const leader = sumVerifierShare(0, ...args, leaderInput);
	expect(() =>
		sumVerifierMessage(leader.verifierShare, helper.verifierShare),
	).toThrow();
	leaderInput.fill(255, 0, 8);
	expect(() => sumVerifierShare(0, ...args, leaderInput)).toThrow();
});

for (const [name, vector] of Object.entries({ histogram0, histogram2 })) {
	it(`${name}: verifies published Histogram shares and output`, () => {
		for (const report of vector.reports) {
			const shares = [0, 1].map((id) =>
				histogramVerifierShare(
					id as 0 | 1,
					vector.length,
					vector.chunk_length,
					bytes(vector.verify_key),
					bytes(vector.ctx),
					bytes(report.nonce),
					bytes(report.public_share),
					bytes(report.input_shares[id]!),
				),
			);
			expect(shares.map((share) => share.verifierShare)).toEqual(
				report.verifier_shares[0]!.map(bytes),
			);
			expect(shares[0]!.jointSeed).toEqual(bytes(report.verifier_messages[0]!));
			expect(shares[1]!.jointSeed).toEqual(bytes(report.verifier_messages[0]!));
			expect(
				histogramVerifierMessage(
					shares[0]!.verifierShare,
					shares[1]!.verifierShare,
					vector.chunk_length,
					bytes(vector.ctx),
				),
			).toEqual(bytes(report.verifier_messages[0]!));
			expect(shares.map((share) => share.outputShare)).toEqual(
				report.out_shares.map(bytes),
			);
		}
	});
}

// Run one report through the production Leader and Helper steps.
function histogramSteps(
	vector: typeof histogram0,
	leaderInput = bytes(vector.reports[0]!.input_shares[0]!),
) {
	const report = vector.reports[0]!;
	const vdaf = prio3Histogram(vector.length, vector.chunk_length);
	const args = [
		bytes(vector.ctx),
		bytes(vector.verify_key),
		bytes(report.nonce),
		bytes(report.public_share),
	] as const;
	const leader = leaderPrio3Init(vdaf, ...args, leaderInput);
	const helper = helperPrio3Init(
		vdaf,
		...args,
		bytes(report.input_shares[1]!),
		leader.outbound,
	);
	return { vdaf, leader, helper };
}

it("completes the published Histogram report through both roles", () => {
	const { vdaf, leader, helper } = histogramSteps(histogram0);
	expect(leaderPrio3Finish(vdaf, leader.state, helper.outbound)).toEqual(
		bytes(histogram0.reports[0]!.out_shares[0]!),
	);
});

for (const [name, vector] of Object.entries({
	badHelperBlind,
	badLeaderBlind,
	badPublicShare,
})) {
	it(`${name}: the Helper rejects the published malformed transcript`, () => {
		expect(() => histogramSteps(vector)).toThrow();
	});
}

it("badVerifierMessage: the Leader rejects the published verifier message", () => {
	const { vdaf, leader } = histogramSteps(badVerifierMessage);
	const message = bytes(badVerifierMessage.reports[0]!.verifier_messages[0]!);
	expect(() =>
		leaderPrio3Finish(
			vdaf,
			leader.state,
			concat(Uint8Array.of(2), uint(message.length, 4), message),
		),
	).toThrow("joint randomness mismatch");
});

it("rejects changed Histogram proof, measurement, blind, and field encoding", () => {
	const original = bytes(histogram0.reports[0]!.input_shares[0]!);
	for (const offset of [0, histogram0.length * 16, original.length - 32]) {
		const changed = original.slice();
		changed[offset]! ^= 1;
		expect(() => histogramSteps(histogram0, changed)).toThrow();
	}
	const nonCanonical = original.slice();
	nonCanonical.fill(255, 0, 16);
	expect(() => histogramSteps(histogram0, nonCanonical)).toThrow();
});

for (const [name, vdaf, values, result] of [
	["Sum", prio3Sum(255), [100, 11], 111n],
	["Histogram", prio3Histogram(4, 2), [2, 1], [0n, 1n, 1n, 0n]],
] as const) {
	it(`${name}: verifies encrypted reports through a mixed DAP 19 batch`, async () => {
		const task = Task.create({ ...taskOptions, minBatchSize: 2, vdaf });
		const client = await Client.create(task, {
			hpke,
			random: deterministicRandom(),
			clock: () => 179999,
		});
		const reports = (await client.prepareReports([...values, values[0]])).map(
			encodeReport,
		);
		// Damage the Helper's ciphertext in the third report.
		const damaged = reports[2]!;
		damaged[damaged.length - 1]! ^= 1;
		const privateKey = bytes(hpkeVector.skRm);
		const verifyKeys = [{ id: 0, key: bytes(sum0.verify_key) }];
		const collector = await collectorKeys();
		const leader = await Leader.create(task, {
			hpkeKeys: [{ configId: 7, privateKey }],
			verifyKeys,
			collector: collector.config,
		});
		const helper = await Helper.create(task, {
			hpkeKeys: [{ configId: 8, privateKey }],
			verifyKeys,
			collector: collector.config,
		});
		const job = await leader.prepare(reports);
		const verified = await helper.verify(job.request!);
		const response = verified.seal();
		const finished = leader.finish(job.state, response);
		expect(
			leader.finish(
				job.state,
				verified.seal([{ id: job.reports[0]!.id, error: "report-replayed" }]),
			)[0],
		).toMatchObject({ error: "report-replayed" });
		expect(finished.map((item) => item.id)).toEqual(
			job.reports.map((item) => item.id),
		);
		expect(finished[2]).toMatchObject({ error: "hpke-decrypt-error" });
		expect(() =>
			leader.finish(
				job.state,
				concat(response.subarray(1), response.subarray(0, 1)),
			),
		).toThrow();
		// Every report is in the 120 s bucket; collect it end to end.
		const bucket = (
			role: Leader | Helper,
			items: readonly { outputShare?: Uint8Array; id: string; time: number }[],
		) =>
			items.reduce<Uint8Array | undefined>(
				(b, item) =>
					item.outputShare ? role.addToBucket(b, item as never) : b,
				undefined,
			)!;
		const leaderBucket = bucket(leader, finished);
		const prepared = (
			await Collector.create(task, {
				configId: collector.config.id,
				privateKey: collector.privateKey,
			})
		).prepare({ start: 120_000, end: 180_000 });
		const collection = leader.collection(
			new Uint8Array(await prepared.request.arrayBuffer()),
		);
		const helperShare = await helper
			.aggregateShare(collection.aggregateShareRequest(leaderBucket))
			.finish(bucket(helper, verified.reports));
		const progress = await prepared.process(
			new Response(await collection.finish(leaderBucket, helperShare), {
				headers: {
					location: "/collection_jobs/1",
					"content-type": "application/ppm-dap;message=collection-job-resp",
				},
			}),
		);
		expect(progress).toMatchObject({
			status: "complete",
			value: result,
			reportCount: 2,
		});
	});
}
