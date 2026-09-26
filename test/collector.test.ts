import { expect, it, vi } from "vitest";
import { concat, uint, vector } from "../src/binary.js";
import { Collector } from "../src/collector.js";
import { collect, executeCollection } from "../src/collector-fetch.js";
import { createSuite } from "../src/hpke.js";
import { prio3Sum, Task } from "../src/index.js";
import {
	decodeCollectionJobRequest,
	decodeCollectionJobResponse,
	encodeCollectionJobRequest,
} from "../src/messages.js";
import { task } from "./fixtures.js";

const jobId = "lc7aUeGpdSNosNlh-UZhKA";
const location = `/tasks/${task.id}/collection_jobs/${jobId}`;
const text = new TextEncoder();

async function keys() {
	const suite = createSuite();
	const pair = await suite.GenerateKeyPair(true);
	return {
		suite,
		pair,
		privateKey: await suite.SerializePrivateKey(pair.privateKey),
	};
}

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
		? collector.resume({ location, start: "10", duration: "2" })
		: collector.prepare({ start: 10, duration: 2 });
	return prepared.process({
		status: 200,
		headers: {
			location,
			"content-type": "application/ppm-dap;message=collection-job-resp",
		},
		body: response,
	});
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
	const collector = new Collector(sumTask, { configId: 7, privateKey });
	const prepared = collector.prepare({ start: 10, duration: 2 });
	const aad = concat(
		Uint8Array.fromBase64(sumTask.id, { alphabet: "base64url" }),
		sumTask.encodeConfiguration(),
		prepared.request.body!,
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
	const response = async (sum: bigint) => ({
		status: 200,
		headers: {
			location: `/tasks/${sumTask.id}/collection_jobs/${jobId}`,
			"content-type": "application/ppm-dap;message=collection-job-resp",
		},
		body: concat(
			uint(100, 8),
			uint(10, 8),
			uint(2, 8),
			await seal(2, 25n),
			await seal(3, sum - 25n),
		),
	});
	await expect(prepared.process(await response(1521n))).resolves.toMatchObject({
		status: "complete",
		sum: 1521n,
	});
	await expect(prepared.process(await response(133701n))).rejects.toMatchObject(
		{ code: "InvalidResponse" },
	);
});

it("decrypts role-bound aggregate shares into an exact bigint count", async () => {
	const { suite, pair, privateKey } = await keys();
	const collector = new Collector(task, { configId: 7, privateKey });
	privateKey.fill(0);
	const prepared = collector.prepare({ start: 10, duration: 2 });
	expect(prepared.request.method).toBe("POST");
	expect(prepared.request.body).toEqual(encodeCollectionJobRequest(10, 2));
	const pending = await prepared.process({
		status: 200,
		headers: { location, "retry-after": "3" },
		body: new Uint8Array(),
	});
	expect(pending.status).toBe("pending");
	if (pending.status !== "pending") return;
	expect(pending.retryAfter).toBe(3);
	expect(collector.resume(pending.state).request.method).toBe("GET");
	const result = await completed(
		collector,
		suite,
		pair.publicKey,
		prepared.request.body!,
		{ resumed: true },
	);
	expect(result).toEqual({
		status: "complete",
		count: 42n,
		reportCount: 100n,
		interval: { start: 10n, duration: 2n },
	});
	await expect(
		completed(collector, suite, pair.publicKey, prepared.request.body!, {
			swapRoles: true,
		}),
	).rejects.toMatchObject({ code: "DecryptionFailed" });
	await expect(
		completed(collector, suite, pair.publicKey, prepared.request.body!, {
			configId: 8,
		}),
	).rejects.toMatchObject({ code: "InvalidResponse" });
	await expect(
		completed(collector, suite, pair.publicKey, prepared.request.body!, {
			count: 101,
		}),
	).rejects.toMatchObject({ code: "InvalidResponse" });
	await expect(
		completed(collector, suite, pair.publicKey, prepared.request.body!, {
			start: 12,
		}),
	).rejects.toMatchObject({ code: "InvalidResponse" });
	await expect(
		completed(
			collector,
			suite,
			pair.publicKey,
			encodeCollectionJobRequest(11, 1),
		),
	).rejects.toMatchObject({ code: "DecryptionFailed" });
	const large = await completed(
		collector,
		suite,
		pair.publicKey,
		prepared.request.body!,
		{ reportCount: 9007199254740993n },
	);
	expect(large.status === "complete" && large.reportCount).toBe(
		9007199254740993n,
	);
	const other = await keys();
	const wrongKey = new Collector(task, {
		configId: 7,
		privateKey: other.privateKey,
	});
	await expect(
		completed(wrongKey, suite, pair.publicKey, prepared.request.body!),
	).rejects.toMatchObject({ code: "DecryptionFailed" });
});

it("rejects wrong collection locations and malformed responses", async () => {
	const { privateKey } = await keys();
	const collector = new Collector(task, { configId: 7, privateKey });
	const prepared = collector.prepare({ start: 10, duration: 2 });
	for (const bad of [
		"https://evil.example/job",
		`/tasks/${task.id}/reports/${jobId}`,
		`${location}?token=x`,
	]) {
		await expect(
			prepared.process({
				status: 200,
				headers: { location: bad },
				body: new Uint8Array(),
			}),
		).rejects.toMatchObject({ code: "InvalidResponse" });
	}
	expect(() =>
		collector.resume({
			location: "https://evil.example/job",
			start: "10",
			duration: "2",
		}),
	).toThrow();
	expect(() =>
		collector.resume({ location, start: "010", duration: "2" }),
	).toThrow();
	expect(() => decodeCollectionJobResponse(new Uint8Array(23))).toThrow();
});

it("sends authenticated requests, polls with a bound, and returns resumable state", async () => {
	const { privateKey } = await keys();
	const collector = new Collector(task, { configId: 7, privateKey });
	const fetch = vi.fn(async (request: Request) => {
		expect(request.headers.get("authorization")).toBe("Bearer test");
		return new Response(null, {
			status: 200,
			headers: request.method === "POST" ? { location } : {},
		});
	});
	const result = await collect(
		collector,
		{ start: 10, duration: 2 },
		{
			fetch,
			headers: { authorization: "Bearer test" },
			maxPolls: 2,
			minDelayMs: 0,
		},
	);
	expect(result.status).toBe("pending");
	expect(fetch.mock.calls.map(([request]) => request.method)).toEqual([
		"POST",
		"GET",
		"GET",
	]);
	if (result.status !== "pending") return;
	await executeCollection(collector.resume(result.state), {
		fetch,
		headers: { authorization: "Bearer test" },
	});
	expect(fetch).toHaveBeenCalledTimes(4);
});

it("stops polling when cancelled", async () => {
	const { privateKey } = await keys();
	const collector = new Collector(task, { configId: 7, privateKey });
	const controller = new AbortController();
	const fetch = vi.fn(async () => {
		setTimeout(() => controller.abort(), 0);
		return new Response(null, { status: 200, headers: { location } });
	});
	await expect(
		collect(
			collector,
			{ start: 10, duration: 2 },
			{ fetch, signal: controller.signal },
		),
	).rejects.toThrow();
	expect(fetch).toHaveBeenCalledTimes(1);
});

it("returns pending state when Retry-After exceeds the auto-poll limit", async () => {
	const { privateKey } = await keys();
	const collector = new Collector(task, { configId: 7, privateKey });
	const fetch = vi.fn(
		async () =>
			new Response(null, {
				status: 200,
				headers: { location, "retry-after": "300" },
			}),
	);
	const result = await collect(
		collector,
		{ start: 10, duration: 2 },
		{ fetch },
	);
	expect(result.status).toBe("pending");
	expect(fetch).toHaveBeenCalledTimes(1);
});
