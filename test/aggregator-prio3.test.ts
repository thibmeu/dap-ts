import { expect, it } from "vitest";
import {
	histogramVerifierMessage,
	histogramVerifierShare,
	sumVerifierMessage,
	sumVerifierShare,
} from "../src/aggregator-prio3.js";
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

for (const [name, vector] of Object.entries({
	badHelperBlind,
	badLeaderBlind,
	badPublicShare,
	badVerifierMessage,
})) {
	it(`${name}: rejects the published malformed Histogram transcript`, () => {
		const report = vector.reports[0]!;
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
		const consistent = () => {
			const message = histogramVerifierMessage(
				shares[0]!.verifierShare,
				shares[1]!.verifierShare,
				vector.chunk_length,
				bytes(vector.ctx),
			);
			if (
				!message.every((byte, i) => byte === shares[0]!.jointSeed[i]) ||
				!message.every((byte, i) => byte === shares[1]!.jointSeed[i]) ||
				(report.verifier_messages[0] &&
					!message.every(
						(byte, i) => byte === bytes(report.verifier_messages[0]!)[i],
					))
			)
				throw new Error("Inconsistent joint randomness");
		};
		expect(consistent).toThrow();
	});
}

it("rejects changed Histogram proof, measurement, blind, and field encoding", () => {
	const vector = histogram0;
	const report = vector.reports[0]!;
	const args = [
		vector.length,
		vector.chunk_length,
		bytes(vector.verify_key),
		bytes(vector.ctx),
		bytes(report.nonce),
		bytes(report.public_share),
	] as const;
	const original = bytes(report.input_shares[0]!);
	const helper = histogramVerifierShare(
		1,
		...args,
		bytes(report.input_shares[1]!),
	);
	const check = (leaderInput: Uint8Array) => {
		const leader = histogramVerifierShare(0, ...args, leaderInput);
		const message = histogramVerifierMessage(
			leader.verifierShare,
			helper.verifierShare,
			vector.chunk_length,
			bytes(vector.ctx),
		);
		if (!message.every((byte, i) => byte === leader.jointSeed[i]))
			throw new Error("Joint randomness mismatch");
	};
	for (const offset of [0, vector.length * 16, original.length - 32]) {
		const changed = original.slice();
		changed[offset]! ^= 1;
		expect(() => check(changed)).toThrow();
	}
	const nonCanonical = original.slice();
	nonCanonical.fill(255, 0, 16);
	expect(() => check(nonCanonical)).toThrow();
});

import { concat } from "../src/binary.js";
import { Client, Helper, Leader, Task } from "../src/index.js";
import { encodeReport } from "../src/messages.js";
import { unshardHistogram } from "../src/prio3-histogram.js";
import { unshardSum } from "../src/prio3-sum.js";
import { prio3Histogram, prio3Sum } from "../src/vdaf.js";
import { deterministicRandom, hpke, taskOptions } from "./fixtures.js";
import hpkeVector from "./vectors/hpke-rfc9180-a1.json";

for (const [name, vdaf, values, result] of [
	["Sum", prio3Sum(255), [100, 11], 111n],
	["Histogram", prio3Histogram(4, 2), [2, 1], [0n, 1n, 1n, 0n]],
] as const) {
	it(`${name}: verifies encrypted reports through a mixed DAP 19 batch`, async () => {
		const task = Task.create({ ...taskOptions, vdaf });
		const client = await Client.create(task, {
			hpke,
			random: deterministicRandom(),
		});
		const reports = (await client.prepareReports([...values, values[0]])).map(
			encodeReport,
		);
		// Damage the Helper's ciphertext in the third report.
		const damaged = reports[2]!;
		damaged[damaged.length - 1]! ^= 1;
		const privateKey = bytes(hpkeVector.skRm);
		const verifyKeys = [{ id: 0, key: bytes(sum0.verify_key) }];
		const leader = await Leader.create(task, {
			hpkeKeys: [{ configId: 7, privateKey }],
			verifyKeys,
		});
		const helper = await Helper.create(task, {
			hpkeKeys: [{ configId: 8, privateKey }],
			verifyKeys,
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
		if (name === "Histogram") {
			// A changed verifier message breaks joint randomness agreement.
			const changed = response.slice();
			changed[16 + 1 + 4]! ^= 1;
			expect(() => leader.finish(job.state, changed)).toThrow();
		}
		expect(() =>
			leader.finish(
				job.state,
				concat(response.subarray(1), response.subarray(0, 1)),
			),
		).toThrow();
		const share = (
			role: Leader | Helper,
			items: readonly { outputShare?: Uint8Array; id: string; time: number }[],
		) =>
			role
				.addToBucket(
					role.addToBucket(undefined, items[0] as never),
					items[1] as never,
				)
				.subarray(0, name === "Sum" ? 8 : 64);
		const shares = [
			share(leader, finished),
			share(helper, verified.reports),
		] as [Uint8Array, Uint8Array];
		if (name === "Sum") expect(unshardSum(shares)).toBe(result);
		else expect(unshardHistogram(shares, 4)).toEqual(result);
	});
}
