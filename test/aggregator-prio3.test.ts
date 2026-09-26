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

import {
	addPrio3OutputShare,
	helperPrio3BatchInit,
	leaderPrio3BatchFinish,
	leaderPrio3BatchInit,
	leaderPrio3JobFinish,
} from "../src/aggregator.js";
import { concat } from "../src/binary.js";
import { DAPClient } from "../src/client.js";
import { decodeReport, encodeReport } from "../src/messages.js";
import { prio3Histogram, unshardHistogram } from "../src/prio3-histogram.js";
import { prio3Sum, unshardSum } from "../src/prio3-sum.js";
import { Task } from "../src/task.js";
import { deterministicRandom, hpke, taskOptions } from "./fixtures.js";
import hpkeVector from "./vectors/hpke-rfc9180-a1.json";

for (const [name, vdaf, values, result] of [
	["Sum", prio3Sum(255), [100, 11], 111n],
	["Histogram", prio3Histogram(4, 2), [2, 1], [0n, 1n, 1n, 0n]],
] as const) {
	it(`${name}: verifies encrypted reports through a mixed DAP 19 batch`, async () => {
		const task = Task.create({ ...taskOptions, vdaf });
		const client = new DAPClient(task, { hpke, random: deterministicRandom() });
		const reports = [];
		for (const value of values)
			reports.push(
				decodeReport(encodeReport(await client.prepareReport(value))),
			);
		const third = decodeReport(
			encodeReport(await client.prepareReport(values[0])),
		);
		const damaged = {
			...third,
			helper: {
				...third.helper,
				payload: third.helper.payload.slice(),
			},
		};
		damaged.helper.payload[0]! ^= 1;
		const leaderKey = { configId: 7, privateKey: bytes(hpkeVector.skRm) };
		const helperKey = { configId: 8, privateKey: bytes(hpkeVector.skRm) };
		const verifyKey = bytes(sum0.verify_key);
		const leader = await leaderPrio3BatchInit(
			task,
			[...reports, damaged],
			leaderKey,
			0,
			verifyKey,
		);
		const helper = await helperPrio3BatchInit(
			task,
			leader.request,
			helperKey,
			0,
			verifyKey,
		);
		const finished = leaderPrio3BatchFinish(
			task,
			leader.reports,
			helper.response,
		);
		expect(finished.map((item) => item.reportId)).toEqual(
			leader.reports.map((item) => item.reportId),
		);
		expect(finished[2]).toMatchObject({ reportError: 5 });
		expect(() =>
			leaderPrio3BatchFinish(
				task,
				leader.reports,
				concat(
					helper.reports[1]!.response,
					helper.reports[0]!.response,
					helper.reports[2]!.response,
				),
			),
		).toThrow();
		if (name === "Histogram") {
			const changed = helper.reports[0]!.response.slice();
			changed[changed.length - 1]! ^= 1;
			expect(() =>
				leaderPrio3JobFinish(
					task,
					leader.reports[0]!.state,
					leader.reports[0]!.reportId,
					changed,
				),
			).toThrow();
		}
		const leaderShares = finished.slice(0, 2).map((item) => {
			if (!("outputShare" in item)) throw new Error("Expected output share");
			return item.outputShare;
		});
		const helperShares = helper.reports.slice(0, 2).map((item) => {
			if (!item.outputShare) throw new Error("Expected output share");
			return item.outputShare;
		});
		if (name === "Sum") {
			expect(
				unshardSum([
					addPrio3OutputShare(task, leaderShares[0]!, leaderShares[1]!),
					addPrio3OutputShare(task, helperShares[0]!, helperShares[1]!),
				]),
			).toBe(result);
		} else {
			expect(
				unshardHistogram(
					[
						addPrio3OutputShare(task, leaderShares[0]!, leaderShares[1]!),
						addPrio3OutputShare(task, helperShares[0]!, helperShares[1]!),
					],
					4,
				),
			).toEqual(result);
		}
	});
}
