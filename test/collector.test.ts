import { expect, it } from "vitest";
import { concat, uint, vector } from "../src/binary.js";
import { Collector } from "../src/collector.js";
import { createSuite, prepareRecipientKey } from "../src/hpke.js";
import {
	prio3Histogram,
	prio3Sum,
	Collector as RootCollector,
	Task,
} from "../src/index.js";
import {
	decodeAggregateShareRequest,
	decodeCollectionJobRequest,
	decodeCollectionJobResponse,
	encodeAggregateShareRequest,
	encodeCollectionJobRequest,
	encodeCollectionJobResponse,
} from "../src/messages.js";
import { task } from "./fixtures.js";

const jobId = "lc7aUeGpdSNosNlh-UZhKA";
const location = `/tasks/${task.id}/collection_jobs/${jobId}`;
const text = new TextEncoder();

it("round trips DAP 19 collection and aggregate share messages", () => {
	const request = encodeCollectionJobRequest(10, 1);
	const checksum = new Uint8Array(32).fill(7);
	const aggregate = encodeAggregateShareRequest(request, 42, checksum);
	expect(decodeAggregateShareRequest(aggregate)).toEqual({
		collectionRequest: request,
		start: 10n,
		duration: 1n,
		reportCount: 42n,
		checksum,
	});
	const malformed = aggregate.slice();
	malformed[43] = 2;
	expect(() => decodeAggregateShareRequest(malformed)).toThrow();
	const ciphertext = {
		configId: 7,
		enc: new Uint8Array(32),
		payload: new Uint8Array(8),
	};
	const response = {
		reportCount: 42n,
		start: 10n,
		duration: 1n,
		leader: ciphertext,
		helper: ciphertext,
	};
	expect(
		decodeCollectionJobResponse(encodeCollectionJobResponse(response)),
	).toEqual(response);
});

async function keys() {
	const suite = createSuite();
	const pair = await suite.GenerateKeyPair(true);
	return {
		suite,
		pair,
		privateKey: await suite.SerializePrivateKey(pair.privateKey),
	};
}

it("does not zero a caller-owned Node Buffer private key", async () => {
	const { privateKey } = await keys();
	const input = Buffer.from(privateKey);
	await prepareRecipientKey(input);
	expect(input).toEqual(Buffer.from(privateKey));
});

async function completed(
	collector: Collector,
	suite: ReturnType<typeof createSuite>,
	publicKey: CryptoKey,
	body: Uint8Array,
	options: {
		swapRoles?: boolean;
		count?: number;
		reportCount?: number | bigint;
		configId?: number;
		resumed?: boolean;
		start?: number;
	} = {},
) {
	const count = options.count ?? 42;
	const reportCount = options.reportCount ?? 100;
	const aad = concat(
		Uint8Array.fromBase64(task.id, { alphabet: "base64url" }),
		task.encodeConfiguration(),
		body,
	);
	const seal = async (role: number, value: number) => {
		const share = new Uint8Array(8);
		new DataView(share.buffer).setBigUint64(0, BigInt(value), true);
		const info = concat(
			text.encode("dap-19 aggregate share"),
			Uint8Array.of(role, 0),
		);
		const result = await suite.Seal(publicKey, share, { info, aad });
		return concat(
			uint(options.configId ?? 7, 1),
			vector(result.encapsulatedSecret, 2),
			vector(result.ciphertext, 4),
		);
	};
	const leader = await seal(options.swapRoles ? 3 : 2, 25);
	const helper = await seal(options.swapRoles ? 2 : 3, count - 25);
	const response = concat(
		uint(reportCount, 8),
		uint(options.start ?? 10, 8),
		uint(2, 8),
		leader,
		helper,
	);
	const prepared = options.resumed
		? collector.resume({ location, start: 600000, end: 720000 })
		: collector.prepare({ start: 600000, end: 720000 });
	return prepared.process(
		new Response(response, {
			headers: {
				location,
				"content-type": "application/ppm-dap;message=collection-job-resp",
			},
		}),
	);
}

it("encodes the DAP 19 time-interval count collection request", () => {
	const encoded = encodeCollectionJobRequest(10, 2);
	expect(encoded).toEqual(
		Uint8Array.fromHex("010010000000000000000a0000000000000002000000000000"),
	);
	expect(decodeCollectionJobRequest(encoded)).toEqual({
		start: 10n,
		duration: 2n,
	});
	for (const [start, duration] of [
		[0, 0],
		[-1, 1],
		[2 ** 53, 1],
		[0xffffffffffffffffn, 1],
	]) {
		expect(() => encodeCollectionJobRequest(start, duration)).toThrow();
	}
	for (const malformed of [
		encoded.slice(0, -1),
		concat(encoded, Uint8Array.of(0)),
		Uint8Array.of(2, ...encoded.slice(1)),
	]) {
		expect(() => decodeCollectionJobRequest(malformed)).toThrow();
	}
});

it("decrypts bounded sum shares and rejects results above the batch bound", async () => {
	const sumTask = Task.create({
		id: task.id,
		leader: task.leader,
		helper: task.helper,
		timePrecision: task.timePrecision,
		minBatchSize: task.minBatchSize,
		batchMode: "time-interval",
		vdaf: prio3Sum(1337),
	});
	const { suite, pair, privateKey } = await keys();
	const collector = await RootCollector.create(sumTask, {
		configId: 7,
		privateKey,
	});
	const prepared = collector.prepare({ start: 600000, end: 720000 });
	const aad = concat(
		Uint8Array.fromBase64(sumTask.id, { alphabet: "base64url" }),
		sumTask.encodeConfiguration(),
		encodeCollectionJobRequest(10, 2),
	);
	const seal = async (role: number, value: bigint) => {
		const share = new Uint8Array(8);
		new DataView(share.buffer).setBigUint64(0, value, true);
		const ciphertext = await suite.Seal(pair.publicKey, share, {
			info: concat(
				text.encode("dap-19 aggregate share"),
				Uint8Array.of(role, 0),
			),
			aad,
		});
		return concat(
			uint(7, 1),
			vector(ciphertext.encapsulatedSecret, 2),
			vector(ciphertext.ciphertext, 4),
		);
	};
	const response = async (sum: bigint) =>
		new Response(
			concat(
				uint(100, 8),
				uint(10, 8),
				uint(2, 8),
				await seal(2, 25n),
				await seal(3, sum - 25n),
			),
			{
				headers: {
					location: `/tasks/${sumTask.id}/collection_jobs/${jobId}`,
					"content-type": "application/ppm-dap;message=collection-job-resp",
				},
			},
		);
	await expect(prepared.process(await response(1521n))).resolves.toMatchObject({
		status: "complete",
		value: 1521n,
	});
	await expect(prepared.process(await response(133701n))).rejects.toMatchObject(
		{ code: "InvalidResponse" },
	);
});

it("decrypts histogram shares and checks the bucket total", async () => {
	const histogramTask = Task.create({
		id: task.id,
		leader: task.leader,
		helper: task.helper,
		timePrecision: task.timePrecision,
		minBatchSize: task.minBatchSize,
		batchMode: "time-interval",
		vdaf: prio3Histogram(4, 2),
	});
	const { suite, pair, privateKey } = await keys();
	const collector = await Collector.create(histogramTask, {
		configId: 7,
		privateKey,
	});
	const prepared = collector.prepare({ start: 600000, end: 720000 });
	const aad = concat(
		Uint8Array.fromBase64(histogramTask.id, { alphabet: "base64url" }),
		histogramTask.encodeConfiguration(),
		encodeCollectionJobRequest(10, 2),
	);
	const seal = async (role: number, buckets: number[]) => {
		const share = new Uint8Array(16 * buckets.length);
		const view = new DataView(share.buffer);
		for (const [i, bucket] of buckets.entries())
			view.setBigUint64(i * 16, BigInt(bucket), true);
		const ciphertext = await suite.Seal(pair.publicKey, share, {
			info: concat(
				text.encode("dap-19 aggregate share"),
				Uint8Array.of(role, 0),
			),
			aad,
		});
		return concat(
			uint(7, 1),
			vector(ciphertext.encapsulatedSecret, 2),
			vector(ciphertext.ciphertext, 4),
		);
	};
	const response = async (helper: number[]) =>
		new Response(
			concat(
				uint(100, 8),
				uint(10, 8),
				uint(2, 8),
				await seal(2, [25, 0, 0, 0]),
				await seal(3, helper),
			),
			{
				headers: {
					location: `/tasks/${histogramTask.id}/collection_jobs/${jobId}`,
					"content-type": "application/ppm-dap;message=collection-job-resp",
				},
			},
		);
	await expect(
		prepared.process(await response([0, 50, 25, 0])),
	).resolves.toMatchObject({
		status: "complete",
		value: [25n, 50n, 25n, 0n],
	});
	await expect(
		prepared.process(await response([0, 49, 25, 0])),
	).rejects.toMatchObject({ code: "InvalidResponse" });
});

it("decrypts role-bound aggregate shares into an exact bigint count", async () => {
	const { suite, pair, privateKey } = await keys();
	const collector = await Collector.create(task, { configId: 7, privateKey });
	privateKey.fill(0);
	const prepared = collector.prepare({ start: 600000, end: 720000 });
	expect(prepared.request.method).toBe("POST");
	expect(prepared.request.url).toBe(
		`https://l/tasks/${task.id}/collection_jobs`,
	);
	expect(new Uint8Array(await prepared.request.arrayBuffer())).toEqual(
		encodeCollectionJobRequest(10, 2),
	);
	const pending = await prepared.process(
		new Response(null, { headers: { location, "retry-after": "3" } }),
	);
	expect(pending.status).toBe("pending");
	if (pending.status !== "pending") return;
	expect(pending.retryAfter).toBe(3);
	expect(collector.resume(pending.state).request.method).toBe("GET");
	const result = await completed(
		collector,
		suite,
		pair.publicKey,
		encodeCollectionJobRequest(10, 2),
		{ resumed: true },
	);
	expect(result).toEqual({
		status: "complete",
		value: 42n,
		reportCount: 100,
		interval: { start: 600000, end: 720000 },
	});
	await expect(
		completed(
			collector,
			suite,
			pair.publicKey,
			encodeCollectionJobRequest(10, 2),
			{
				swapRoles: true,
			},
		),
	).rejects.toMatchObject({ code: "DecryptionFailed" });
	await expect(
		completed(
			collector,
			suite,
			pair.publicKey,
			encodeCollectionJobRequest(10, 2),
			{
				configId: 8,
			},
		),
	).rejects.toMatchObject({ code: "InvalidResponse" });
	await expect(
		completed(
			collector,
			suite,
			pair.publicKey,
			encodeCollectionJobRequest(10, 2),
			{
				count: 101,
			},
		),
	).rejects.toMatchObject({ code: "InvalidResponse" });
	await expect(
		completed(
			collector,
			suite,
			pair.publicKey,
			encodeCollectionJobRequest(10, 2),
			{
				start: 12,
			},
		),
	).rejects.toMatchObject({ code: "InvalidResponse" });
	await expect(
		completed(
			collector,
			suite,
			pair.publicKey,
			encodeCollectionJobRequest(11, 1),
		),
	).rejects.toMatchObject({ code: "DecryptionFailed" });
	await expect(
		completed(
			collector,
			suite,
			pair.publicKey,
			encodeCollectionJobRequest(10, 2),
			{
				reportCount: 9007199254740993n,
			},
		),
	).rejects.toMatchObject({ code: "InvalidResponse" });
	const other = await keys();
	const wrongKey = await Collector.create(task, {
		configId: 7,
		privateKey: other.privateKey,
	});
	await expect(
		completed(
			wrongKey,
			suite,
			pair.publicKey,
			encodeCollectionJobRequest(10, 2),
		),
	).rejects.toMatchObject({ code: "DecryptionFailed" });
});

it("rejects wrong collection locations and malformed responses", async () => {
	const { privateKey } = await keys();
	const collector = await Collector.create(task, { configId: 7, privateKey });
	const prepared = collector.prepare({ start: 600000, end: 720000 });
	for (const bad of ["https://evil.example/job", `${location}#fragment`, ""]) {
		await expect(
			prepared.process(new Response(null, { headers: { location: bad } })),
		).rejects.toMatchObject({ code: "InvalidResponse" });
	}
	// DAP 19, 3.2 lets the Leader choose the job identifier and path.
	for (const good of [
		`/tasks/${task.id}/reports/${jobId}`,
		`${location}?token=x`,
		"/collection/9e1a2b",
	]) {
		const progress = await prepared.process(
			new Response(null, { headers: { location: good } }),
		);
		expect(progress.status).toBe("pending");
	}
	expect(() =>
		collector.resume({
			location: "https://evil.example/job",
			start: 600000,
			end: 720000,
		}),
	).toThrow();
	for (const [start, end] of [
		[600001, 720000],
		[720000, 720000],
		[-60000, 0],
	])
		expect(() => collector.resume({ location, start, end } as never)).toThrow();
	expect(() => decodeCollectionJobResponse(new Uint8Array(23))).toThrow();
});
