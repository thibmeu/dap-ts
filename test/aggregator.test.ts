import { Buffer } from "node:buffer";
import { CipherSuite } from "hpke";
import { expect, it, vi } from "vitest";
import {
	countVerifierMessage,
	countVerifierShare,
	helperPrio3Init,
	leaderPrio3Finish,
	leaderPrio3Init,
} from "../src/aggregator.js";
import { concat, uint, vector } from "../src/binary.js";
import { createSuite } from "../src/hpke.js";
import {
	Client,
	Collector,
	DAPError,
	Helper,
	Leader,
	prio3Count,
	problemResponse,
	type ReportId,
	Task,
} from "../src/index.js";
import {
	decodeReport,
	encodeCollectionJobRequest,
	encodeReport,
	encodeUploadRequest,
} from "../src/messages.js";
import {
	collectorKeys,
	deterministicRandom,
	hpke,
	task,
	taskOptions,
} from "./fixtures.js";
import hpkeVector from "./vectors/hpke-rfc9180-a1.json";
import count0 from "./vectors/Prio3Count_0.json";
import count2 from "./vectors/Prio3Count_2.json";
import badGadget from "./vectors/Prio3Count_bad_gadget_poly.json";
import badHelper from "./vectors/Prio3Count_bad_helper_seed.json";
import badMeasurement from "./vectors/Prio3Count_bad_meas_share.json";
import badWire from "./vectors/Prio3Count_bad_wire_seed.json";

const bytes = (hex: string) => Uint8Array.fromHex(hex);
const count = prio3Count();

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
			const steps = [count, args[1], args[0], args[2], args[3]] as const;
			const leader = leaderPrio3Init(...steps, leaderInput);
			const helper = helperPrio3Init(...steps, helperInput, leader.outbound);
			expect(leaderPrio3Finish(count, leader.state, helper.outbound)).toEqual(
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
		const steps = [count, args[1], args[0], args[2], args[3]] as const;
		const leader = leaderPrio3Init(...steps, bytes(report.input_shares[0]!));
		expect(() =>
			helperPrio3Init(
				...steps,
				bytes(report.input_shares[1]!),
				leader.outbound,
			),
		).toThrow();
	});
}

it("rejects truncated and non-canonical peer messages", () => {
	const report = count0.reports[0]!;
	const args = [
		count,
		bytes(count0.ctx),
		bytes(count0.verify_key),
		bytes(report.nonce),
		bytes(report.public_share),
	] as const;
	const leader = leaderPrio3Init(...args, bytes(report.input_shares[0]!));
	const helperInput = bytes(report.input_shares[1]!);
	expect(() =>
		helperPrio3Init(...args, helperInput, leader.outbound.subarray(0, 4)),
	).toThrow();
	const changed = leader.outbound.slice();
	changed.fill(255, 5, 13);
	expect(() => helperPrio3Init(...args, helperInput, changed)).toThrow();
	const helper = helperPrio3Init(...args, helperInput, leader.outbound);
	expect(() =>
		leaderPrio3Finish(
			count,
			leader.state,
			Uint8Array.of(...helper.outbound, 0),
		),
	).toThrow();
});

const privateKey = bytes(hpkeVector.skRm);
const verifyKeys = [{ id: 0, key: new Uint8Array(32) }];
const NOW = 179999;
const roles = async (options: { maxSkewSeconds?: number } = {}) => ({
	leader: await Leader.create(task, {
		hpkeKeys: [{ configId: 7, privateKey }],
		verifyKeys,
		clock: () => NOW,
		...options,
	}),
	helper: await Helper.create(task, {
		hpkeKeys: [{ configId: 8, privateKey }],
		verifyKeys,
		clock: () => NOW,
		...options,
	}),
});
const client = () =>
	Client.create(task, {
		hpke,
		random: deterministicRandom(),
		clock: () => NOW,
	});

it("serves every configured HPKE key and decrypts with each", async () => {
	const other = await createSuite().GenerateKeyPair(true);
	const otherPrivate = await createSuite().SerializePrivateKey(
		other.privateKey,
	);
	const otherPublic = await createSuite().SerializePublicKey(other.publicKey);
	const leader = await Leader.create(task, {
		hpkeKeys: [
			{ configId: 9, privateKey: otherPrivate },
			{ configId: 7, privateKey },
		],
		verifyKeys,
		clock: () => NOW,
	});
	expect(leader.hpkeConfigs.configs.map((c) => [c.id, c.publicKey])).toEqual([
		[9, otherPublic],
		[7, bytes(hpkeVector.pkRm)],
	]);
	const rotated = await Client.create(task, {
		hpke: { leader: leader.hpkeConfigs, helper: hpke.helper },
		clock: () => NOW,
	});
	const old = await client();
	const job = await leader.prepare([
		encodeReport(await rotated.prepareReport(1)),
		encodeReport(await old.prepareReport(1)),
	]);
	expect(job.rejected).toEqual([]);
	await expect(
		Leader.create(task, {
			hpkeKeys: [
				{ configId: 7, privateKey },
				{ configId: 7, privateKey },
			],
			verifyKeys,
		}),
	).rejects.toThrow(DAPError);
});

it("checks uploads and answers in request order", async () => {
	const { leader } = await roles();
	const c = await client();
	const [a, b, d] = await c.prepareReports([1, 0, 1]);
	const decoded = decodeReport(encodeReport(b!));
	const unknownKey = encodeReport({
		...decoded,
		leader: { ...decoded.leader, configId: 99 },
	});
	const future = encodeReport(
		await c.prepareReport(1, { time: NOW + 3_600_000 }),
	);
	const upload = leader.upload(
		encodeUploadRequest([a!, unknownKey, future, d!, a!]),
	);
	expect(upload.reports.map((r) => r.id)).toEqual([a!.id, d!.id]);
	expect(upload.reports[0]!.time).toBe(a!.time);
	expect(upload.reports[0]!.report).toEqual(encodeReport(a!));
	expect(upload.rejected.map((r) => r.error)).toEqual([
		"hpke-unknown-config-id",
		"report-too-early",
		"report-replayed",
	]);
	const errors = upload.respond([{ id: d!.id, error: "batch-collected" }]);
	const id = (report: { id: string }) =>
		Uint8Array.fromBase64(report.id, {
			alphabet: "base64url",
		});
	expect(errors).toEqual(
		concat(
			id(b!),
			Uint8Array.of(4),
			new Uint8Array(decodeReport(future).metadata.id),
			Uint8Array.of(8),
			id(d!),
			Uint8Array.of(1),
			id(a!),
			Uint8Array.of(2),
		),
	);
	expect(leader.upload(encodeUploadRequest([a!])).respond()).toEqual(
		new Uint8Array(),
	);
	expect(() =>
		upload.respond([{ id: b!.id, error: "report-replayed" }]),
	).toThrow();
	expect(() => leader.upload(new Uint8Array(3))).toThrow(DAPError);
	const bounded = await Leader.create(
		Task.create({
			...taskOptions,
			extensions: [{ type: 1, data: concat(uint(3, 8), uint(2, 8)) }],
		}),
		{ hpkeKeys: [{ configId: 7, privateKey }], verifyKeys, clock: () => NOW },
	);
	expect(bounded.upload(encodeUploadRequest([a!])).rejected).toEqual([
		{ id: a!.id, error: "report-dropped" },
	]);
});

it("runs a mixed job and keeps results in report order", async () => {
	const { leader, helper } = await roles();
	const c = await client();
	const [first, second, third, fourth] = (
		await c.prepareReports([1, 1, 0, 1])
	).map(encodeReport);
	const damaged = decodeReport(second!);
	damaged.helper.payload[0]! ^= 1;
	const noisy = decodeReport(fourth!);
	const unsupported = encodeReport({
		...noisy,
		metadata: {
			...noisy.metadata,
			publicExtensions: [{ type: 500, data: new Uint8Array() }],
		},
	});
	const job = await leader.prepare([
		first!,
		encodeReport(damaged),
		third!,
		unsupported,
	]);
	expect(job.rejected).toMatchObject([{ error: "invalid-message" }]);
	expect(job.reports).toHaveLength(3);
	const verified = await helper.verify(job.request!);
	expect(verified.reports.map((r) => r.error)).toEqual([
		undefined,
		"hpke-decrypt-error",
		undefined,
	]);
	const replayed = verified.reports[2]!.id;
	const results = leader.finish(
		job.state,
		verified.seal([{ id: replayed, error: "report-replayed" }]),
	);
	expect(results.map((r) => [r.id, r.error])).toEqual([
		[job.reports[0]!.id, undefined],
		[job.reports[1]!.id, "hpke-decrypt-error"],
		[job.reports[2]!.id, "report-replayed"],
	]);
	expect(results[0]!.time).toBe(120000);
	// A response that does not line up with the job is refused.
	const response = verified.seal();
	for (const bad of [
		response.subarray(0, 40),
		concat(response, Uint8Array.of(0)),
	])
		expect(() => leader.finish(job.state, bad)).toThrow(DAPError);
	expect(() =>
		verified.seal([
			{ id: "AAAAAAAAAAAAAAAAAAAAAA" as ReportId, error: "report-replayed" },
		]),
	).toThrow();
	await expect(leader.prepare([first!, first!])).rejects.toThrow(DAPError);
	const none = await leader.prepare([unsupported]);
	expect(none.request).toBeUndefined();
});

it("answers job-level Helper failures with DAP problem types", async () => {
	const { leader, helper } = await roles();
	const job = await leader.prepare([
		encodeReport(await (await client()).prepareReport(1)),
	]);
	const request = job.request!;
	const inits = request.subarray(7);
	const failure = async (body: Uint8Array) => {
		try {
			await helper.verify(body);
		} catch (error) {
			return (error as DAPError).type;
		}
	};
	expect(
		await failure(
			concat(
				Uint8Array.of(0),
				vector(Uint8Array.of(1), 4),
				vector(new Uint8Array(), 2),
				inits,
			),
		),
	).toBe("invalidAggregationParameter");
	expect(
		await failure(
			concat(
				Uint8Array.of(0),
				vector(new Uint8Array(), 4),
				vector(Uint8Array.of(0, 1, 0, 0), 2),
				inits,
			),
		),
	).toBe("unsupportedExtension");
	expect(await failure(concat(request, inits))).toBe("invalidMessage");
	expect(await failure(request.subarray(0, 7))).toBe("invalidMessage");
	const unknownKey = request.slice();
	unknownKey[0] = 5;
	expect((await helper.verify(unknownKey)).reports[0]!.error).toBe(
		"unknown-verification-key-id",
	);
	const problem = problemResponse(
		new DAPError("InvalidMessage", "Nope", { type: "batchMismatch" }),
		task.id,
	);
	expect(problem.status).toBe(400);
	expect(problem.headers.get("content-type")).toBe("application/problem+json");
	expect(await problem.json()).toMatchObject({
		type: "urn:ietf:params:ppm:dap:error:batchMismatch",
		taskid: task.id,
	});
	const hidden = problemResponse(new Error("database password is hunter2"));
	expect(hidden.status).toBe(500);
	expect(await hidden.text()).not.toContain("hunter2");
});

it("honours the clock and skew allowance", async () => {
	const c = await client();
	const report = encodeReport(
		await c.prepareReport(1, { time: NOW + 1_200_000 }),
	);
	const { leader } = await roles();
	expect((await leader.prepare([report])).rejected).toMatchObject([
		{ error: "report-too-early" },
	]);
	const { leader: lenient } = await roles({ maxSkewSeconds: 1500 });
	expect((await lenient.prepare([report])).rejected).toEqual([]);
	await expect(roles({ maxSkewSeconds: -1 })).rejects.toThrow(DAPError);
});

it("collects merged buckets end to end", async () => {
	const keys = await collectorKeys();
	// Buffer.slice() aliases, and callers may wipe or reuse key buffers after
	// create(): each role must own its keys, and buckets may be offset views.
	const leaderKey = Buffer.alloc(32, 1);
	const collectorKey = Buffer.from(keys.config.publicKey);
	const view = (bucket: Uint8Array) =>
		Buffer.concat([Buffer.alloc(3, 0xaa), bucket]).subarray(3);
	const options = {
		clock: () => 10_000_000,
		collector: { ...keys.config, publicKey: collectorKey },
	};
	const leader = await Leader.create(task, {
		...options,
		verifyKeys: [{ id: 0, key: leaderKey }],
		hpkeKeys: [{ configId: 7, privateKey }],
	});
	const helper = await Helper.create(task, {
		...options,
		verifyKeys: [{ id: 0, key: Buffer.alloc(32, 1) }],
		hpkeKeys: [{ configId: 8, privateKey }],
	});
	leaderKey.fill(0);
	collectorKey.fill(0);
	const c = await Client.create(task, { hpke });
	// Reports in minutes 2 and 4 of a three-bucket query; minute 3 is empty.
	const reports = [
		...(await c.prepareReports(Array(60).fill(1), { time: 120_000 })),
		...(await c.prepareReports([...Array(50).fill(1), 0, 0], {
			time: 240_000,
		})),
	].map(encodeReport);
	const job = await leader.prepare(reports);
	const verified = await helper.verify(job.request!);
	// The Leader's wiped key buffer must not change its verification key.
	expect(verified.reports.filter((report) => "error" in report)).toEqual([]);
	const buckets = {
		leader: new Map<number, Uint8Array>(),
		helper: new Map<number, Uint8Array>(),
	};
	for (const report of verified.reports)
		buckets.helper.set(
			report.time,
			view(
				helper.addToBucket(buckets.helper.get(report.time), report as never),
			),
		);
	for (const report of leader.finish(job.state, verified.seal()))
		buckets.leader.set(
			report.time,
			view(
				leader.addToBucket(buckets.leader.get(report.time), report as never),
			),
		);
	expect(leader.bucketReportCount(buckets.leader.get(240_000)!)).toBe(52);

	const collector = await Collector.create(task, {
		configId: keys.config.id,
		privateKey: keys.privateKey,
	});
	const prepared = collector.prepare({ start: 120_000, end: 300_000 });
	const collection = leader.collection(
		new Uint8Array(await prepared.request.arrayBuffer()),
	);
	expect(collection.interval).toEqual({ start: 120_000, end: 300_000 });
	const range = (interval: { start: number; end: number }) =>
		Array.from(
			{ length: (interval.end - interval.start) / 60_000 },
			(_, i) => interval.start + i * 60_000,
		);
	const merge = (
		role: typeof leader | typeof helper,
		map: Map<number, Uint8Array>,
		interval: { start: number; end: number },
	) =>
		role.mergeBuckets(range(interval).flatMap((time) => map.get(time) ?? []));
	const leaderBucket = merge(leader, buckets.leader, collection.interval);
	const shareRequest = collection.aggregateShareRequest(leaderBucket);
	const share = helper.aggregateShare(shareRequest);
	expect(share.interval).toEqual(collection.interval);
	// A Helper that saw a different batch refuses with batchMismatch.
	// Adding to a bucket must not change the caller's input bytes.
	const helperBucket = view(merge(helper, buckets.helper, share.interval));
	await expect(
		share.finish(
			helper.addToBucket(helperBucket, verified.reports[0] as never),
		),
	).rejects.toMatchObject({ type: "batchMismatch" });
	const helperShare = await share.finish(helperBucket);
	const response = await collection.finish(leaderBucket, helperShare);
	const result = await prepared.process(
		new Response(response, {
			headers: {
				location: "/tasks/x/collection_jobs/y",
				"content-type": "application/ppm-dap;message=collection-job-resp",
			},
		}),
	);
	expect(result).toEqual({
		status: "complete",
		value: 110n,
		reportCount: 112,
		interval: { start: 120_000, end: 300_000 },
	});
	// Below the task's minimum batch size, both roles refuse.
	const small = leader.collection(encodeCollectionJobRequest(2, 1));
	expect(() => small.aggregateShareRequest(leader.mergeBuckets([]))).toThrow(
		expect.objectContaining({ type: "invalidBatchSize" }),
	);
	await expect(
		Leader.create(task, {
			verifyKeys,
			hpkeKeys: [{ configId: 7, privateKey }],
		}).then((plain) =>
			plain
				.collection(encodeCollectionJobRequest(2, 3))
				.finish(leaderBucket, helperShare),
		),
	).rejects.toThrow("No collector HPKE configuration");
});

it("refills four report slots and preserves order when opens finish out of order", async () => {
	const { leader, helper } = await roles();
	const c = await client();
	const reports = (await c.prepareReports(Array(9).fill(1))).map(encodeReport);
	const original = CipherSuite.prototype.Open;
	async function held<T>(run: () => Promise<T>): Promise<T> {
		const releases: (() => void)[] = [];
		let active = 0,
			peak = 0;
		const spy = vi
			.spyOn(CipherSuite.prototype, "Open")
			.mockImplementation(async function (...args) {
				const gate = new Promise<void>((resolve) => releases.push(resolve));
				active++;
				peak = Math.max(peak, active);
				try {
					const result = await original.apply(this, args);
					await gate;
					return result;
				} finally {
					active--;
				}
			});
		const pending = run();
		try {
			await vi.waitFor(() => expect(releases).toHaveLength(4));
			// Keep the first three held while the fourth slot processes the rest.
			for (let count = 5; count <= 9; count++) {
				releases[count - 2]!();
				await vi.waitFor(() => expect(releases).toHaveLength(count));
			}
			expect(peak).toBe(4);
			for (const release of [...releases].reverse()) release();
			return await pending;
		} finally {
			for (const release of releases) release();
			await pending.catch(() => {});
			spy.mockRestore();
		}
	}
	const job = await held(() => leader.prepare(reports));
	const expected = reports.map((report) =>
		decodeReport(report).metadata.id.toBase64({
			alphabet: "base64url",
			omitPadding: true,
		}),
	);
	expect(job.reports.map((report) => report.id)).toEqual(expected);
	const verified = await held(() => helper.verify(job.request!));
	expect(verified.reports.map((report) => report.id)).toEqual(expected);
	const finished = leader.finish(job.state, verified.seal());
	expect(finished.map((report) => report.id)).toEqual(expected);
	expect(finished.every((report) => report.outputShare)).toBe(true);
});

it("drains active opens before rejecting an unexpected job failure", async () => {
	const failure = new Error("clock failed");
	let fail = false,
		calls = 0;
	const leader = await Leader.create(task, {
		hpkeKeys: [{ configId: 7, privateKey }],
		verifyKeys,
		clock: () => {
			calls++;
			if (fail) throw failure;
			return NOW;
		},
	});
	const c = await client();
	const reports = (await c.prepareReports(Array(9).fill(1))).map(encodeReport);
	const releases: (() => void)[] = [];
	const original = CipherSuite.prototype.Open;
	const spy = vi
		.spyOn(CipherSuite.prototype, "Open")
		.mockImplementation(async function (...args) {
			const gate = new Promise<void>((resolve) => releases.push(resolve));
			const result = await original.apply(this, args);
			await gate;
			return result;
		});
	let settled = false;
	const pending = leader.prepare(reports);
	void pending.then(
		() => {
			settled = true;
		},
		() => {
			settled = true;
		},
	);
	try {
		await vi.waitFor(() => expect(releases).toHaveLength(4));
		fail = true;
		releases[3]!();
		await vi.waitFor(() => expect(calls).toBe(5));
		expect(settled).toBe(false);
		for (const release of releases) release();
		await expect(pending).rejects.toBe(failure);
		expect(releases).toHaveLength(4);
	} finally {
		for (const release of releases) release();
		await pending.catch(() => {});
		spy.mockRestore();
	}
});
