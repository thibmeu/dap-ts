import { expect, it } from "vitest";
import {
	addCountOutputShare,
	countVerifierMessage,
	countVerifierShare,
	helperCountInit,
	helperCountJobInit,
	leaderCountFinish,
	leaderCountInit,
	leaderCountJobFinish,
	leaderCountJobInit,
	openCountInputShare,
} from "../src/aggregator.js";
import { concat, uint } from "../src/binary.js";
import { DAPClient } from "../src/client.js";
import type { DAPError } from "../src/errors.js";
import { decodeReport, encodeReport } from "../src/messages.js";
import { unshardCount } from "../src/prio3-count.js";
import { Task } from "../src/task.js";
import { deterministicRandom, hpke, task, taskOptions } from "./fixtures.js";
import hpkeVector from "./vectors/hpke-rfc9180-a1.json";
import count0 from "./vectors/Prio3Count_0.json";
import count2 from "./vectors/Prio3Count_2.json";
import badGadget from "./vectors/Prio3Count_bad_gadget_poly.json";
import badHelper from "./vectors/Prio3Count_bad_helper_seed.json";
import badMeasurement from "./vectors/Prio3Count_bad_meas_share.json";
import badWire from "./vectors/Prio3Count_bad_wire_seed.json";

const bytes = (hex: string) => Uint8Array.fromHex(hex);

for (const [name, vector] of Object.entries({ count0, count2 })) {
	it(`${name}: matches published verifier shares and completes the two roles`, () => {
		for (const report of vector.reports) {
			const args = [
				bytes(vector.verify_key),
				bytes(vector.ctx),
				bytes(report.nonce),
				bytes(report.public_share),
			] as const;
			const leaderInput = bytes(report.input_shares[0]!);
			const helperInput = bytes(report.input_shares[1]!);
			const leaderShare = countVerifierShare(0, ...args, leaderInput);
			const helperShare = countVerifierShare(1, ...args, helperInput);
			expect([leaderShare, helperShare]).toEqual(
				report.verifier_shares[0]!.map(bytes),
			);
			expect(countVerifierMessage(leaderShare, helperShare)).toEqual(
				bytes(report.verifier_messages[0]!),
			);
			const leader = leaderCountInit(...args, leaderInput);
			const helper = helperCountInit(...args, helperInput, leader.outbound);
			expect(leaderCountFinish(leader.state, helper.outbound)).toEqual(
				bytes(report.out_shares[0]!),
			);
			expect(helper.outputShare).toEqual(bytes(report.out_shares[1]!));
		}
	});
}

for (const [name, vector] of Object.entries({
	badGadget,
	badHelper,
	badMeasurement,
	badWire,
})) {
	it(`${name}: matches published verifier shares and rejects the proof`, () => {
		const report = vector.reports[0]!;
		const args = [
			bytes(vector.verify_key),
			bytes(vector.ctx),
			bytes(report.nonce),
			bytes(report.public_share),
		] as const;
		const leaderShare = countVerifierShare(
			0,
			...args,
			bytes(report.input_shares[0]!),
		);
		const helperShare = countVerifierShare(
			1,
			...args,
			bytes(report.input_shares[1]!),
		);
		expect([leaderShare, helperShare]).toEqual(
			report.verifier_shares[0]!.map(bytes),
		);
		expect(() => countVerifierMessage(leaderShare, helperShare)).toThrow();
		const leader = leaderCountInit(...args, bytes(report.input_shares[0]!));
		expect(() =>
			helperCountInit(...args, bytes(report.input_shares[1]!), leader.outbound),
		).toThrow();
	});
}

it("rejects truncated and non-canonical peer messages", () => {
	const report = count0.reports[0]!;
	const args = [
		bytes(count0.verify_key),
		bytes(count0.ctx),
		bytes(report.nonce),
		bytes(report.public_share),
	] as const;
	const leader = leaderCountInit(...args, bytes(report.input_shares[0]!));
	const helperInput = bytes(report.input_shares[1]!);
	expect(() =>
		helperCountInit(...args, helperInput, leader.outbound.subarray(0, 4)),
	).toThrow();
	const changed = leader.outbound.slice();
	changed.fill(255, 5, 13);
	expect(() => helperCountInit(...args, helperInput, changed)).toThrow();
	const helper = helperCountInit(...args, helperInput, leader.outbound);
	expect(() =>
		leaderCountFinish(leader.state, Uint8Array.of(...helper.outbound, 0)),
	).toThrow();
});

it("processes an encrypted DAP 19 report through a one-report aggregation job", async () => {
	const client = new DAPClient(task, {
		hpke,
		random: deterministicRandom(),
		clock: () => 179999,
	});
	const report = decodeReport(encodeReport(await client.prepareReport(1)));
	const leaderKey = { configId: 7, privateKey: bytes(hpkeVector.skRm) };
	const helperKey = { configId: 8, privateKey: bytes(hpkeVector.skRm) };
	const verifyKey = bytes(count0.verify_key);
	const leader = await leaderCountJobInit(
		task,
		report,
		leaderKey,
		3,
		verifyKey,
	);
	const helper = await helperCountJobInit(
		task,
		leader.request,
		helperKey,
		3,
		verifyKey,
	);
	const result = leaderCountJobFinish(
		leader.state,
		leader.reportId,
		helper.response,
	);
	expect("outputShare" in result).toBe(true);
	if (!("outputShare" in result) || !helper.outputShare)
		throw new Error("Expected output shares");
	expect(unshardCount([result.outputShare, helper.outputShare])).toBe(1n);
	expect(
		await helperCountJobInit(task, leader.request, helperKey, 3, verifyKey),
	).toEqual(helper);
	expect(
		await helperCountJobInit(task, leader.request, helperKey, 4, verifyKey),
	).toMatchObject({
		response: Uint8Array.of(...report.metadata.id, 2, 9),
	});
	const wrongTaskReport = { ...report, publicShare: Uint8Array.of(0) };
	await expect(
		openCountInputShare(
			task,
			"leader",
			wrongTaskReport.metadata,
			wrongTaskReport.publicShare,
			wrongTaskReport.leader,
			leaderKey,
		),
	).rejects.toThrow();
	await expect(
		openCountInputShare(
			task,
			"leader",
			report.metadata,
			report.publicShare,
			report.leader,
			helperKey,
		),
	).rejects.toThrow();
	const tampered = leader.request.slice();
	tampered[tampered.length - 1] ^= 1;
	const rejected = await helperCountJobInit(
		task,
		tampered,
		helperKey,
		3,
		verifyKey,
	);
	expect(
		leaderCountJobFinish(leader.state, leader.reportId, rejected.response),
	).toEqual({ reportError: 6 });
	expect(() =>
		leaderCountJobFinish(leader.state, new Uint8Array(16), helper.response),
	).toThrow();
});

it("adds canonical Count output shares", () => {
	const one = Uint8Array.of(1, 0, 0, 0, 0, 0, 0, 0);
	expect(addCountOutputShare(one, one)).toEqual(
		Uint8Array.of(2, 0, 0, 0, 0, 0, 0, 0),
	);
	expect(() => addCountOutputShare(one, new Uint8Array(7))).toThrow();
});

it("rejects future and out-of-task-interval Count reports before decryption", async () => {
	const client = new DAPClient(task, {
		hpke,
		random: deterministicRandom(),
		clock: () => 179999,
	});
	const report = decodeReport(encodeReport(await client.prepareReport(1)));
	const leaderKey = { configId: 7, privateKey: bytes(hpkeVector.skRm) };
	const future = { ...report.metadata, time: 20n };
	await expect(
		openCountInputShare(
			task,
			"leader",
			future,
			report.publicShare,
			report.leader,
			leaderKey,
			179999,
		),
	).rejects.toMatchObject({
		code: "ReportTooEarly",
	} satisfies Partial<DAPError>);
	const bounded = Task.create({
		...taskOptions,
		extensions: [{ type: 1, data: concat(uint(3, 8), uint(2, 8)) }],
	});
	await expect(
		openCountInputShare(
			bounded,
			"leader",
			report.metadata,
			report.publicShare,
			report.leader,
			leaderKey,
			179999,
		),
	).rejects.toMatchObject({
		code: "ReportDropped",
	} satisfies Partial<DAPError>);
	const invalidExtension = {
		...report.metadata,
		publicExtensions: [{ type: 500, data: new Uint8Array() }],
	};
	await expect(
		openCountInputShare(
			task,
			"leader",
			invalidExtension,
			report.publicShare,
			report.leader,
			leaderKey,
			179999,
		),
	).rejects.toMatchObject({
		code: "InvalidReport",
	} satisfies Partial<DAPError>);
});
