import { describe, expect, it } from "vitest";
import {
	DAPError,
	HpkeConfigList,
	prio3Count,
	prio3Histogram,
	prio3Sum,
	Task,
} from "../src/index.js";
import {
	decodeHpkeConfigList,
	decodeReport,
	decodeTaskConfiguration,
	decodeUploadErrors,
	decodeUploadRequest,
	encodeExtensions,
	encodeHpkeConfigList,
	encodeReport,
	encodeTaskConfiguration,
	encodeUploadRequest,
} from "../src/messages.js";
import { config, hex, task, taskOptions, taskWire, text } from "./fixtures.js";

it("encodes large upload lists without an argument-count limit", () => {
	const reports = Array.from({ length: 150_000 }, () => Uint8Array.of(42));
	expect(encodeUploadRequest(reports)).toEqual(
		new Uint8Array(150_000).fill(42),
	);
});

it("rejects oversized extension and HPKE lists with protocol errors", () => {
	expect(() =>
		encodeExtensions([{ type: 1, data: new Uint8Array(65532) }]),
	).toThrow(DAPError);
	expect(() => encodeHpkeConfigList(Array(257).fill(config))).toThrow(DAPError);
});

describe("task configuration", () => {
	it("matches a hand-derived DAP 19 encoding", () => {
		expect(task.encodeConfiguration()).toEqual(taskWire);
		const decoded = decodeTaskConfiguration(taskWire);
		expect(decoded).toEqual({
			info: text("p"),
			leader: text("https://l/"),
			helper: text("https://h/"),
			timePrecision: 60n,
			minBatchSize: 100n,
			batchMode: 1,
			batchConfig: new Uint8Array(),
			vdafType: 1,
			vdafConfig: new Uint8Array(),
			extensions: [],
		});
		expect(
			Task.decode({ id: task.id, configuration: taskWire })
				.expect(prio3Count())
				.encodeConfiguration(),
		).toEqual(taskWire);
	});
	it("rejects every truncated prefix and trailing bytes", () => {
		for (let i = 0; i < taskWire.length; i++)
			expect(() => decodeTaskConfiguration(taskWire.slice(0, i))).toThrow(
				DAPError,
			);
		expect(() =>
			decodeTaskConfiguration(new Uint8Array([...taskWire, 0])),
		).toThrow();
		expect(() =>
			decodeTaskConfiguration(taskWire, { maxTaskInfoSize: 0 }),
		).toThrow();
	});
	it("preserves agreed URL bytes and owns its configuration", () => {
		const leader = "https://LEADER.example:443/%7e/";
		const original = Task.create({ ...taskOptions, leader });
		const encoded = original.encodeConfiguration();
		const decoded = Task.decode({ id: task.id, configuration: encoded });
		encoded.fill(0);
		decoded.info.fill(0);
		expect(decoded.leader).toBe(leader);
		expect(decoded.encodeConfiguration()).toEqual(
			original.encodeConfiguration(),
		);
		expect(Object.isFrozen(decoded)).toBe(true);
	});
	it("validates provisioning and immutable task parameters", () => {
		for (const leader of [
			"http://l/",
			"https://u:p@l/",
			"https://l/?x",
			"https://l/#x",
			"https://l/%zz",
			"https://l/é",
			"https://l/\n",
			"https://l/\\x",
		]) {
			expect(() => Task.create({ ...taskOptions, leader })).toThrow();
		}
		for (const timePrecision of [
			0,
			-1,
			0.1,
			NaN,
			Infinity,
			Number.MAX_SAFE_INTEGER + 1,
		])
			expect(() => Task.create({ ...taskOptions, timePrecision })).toThrow();
		for (const id of ["", `${task.id}=`, `${task.id.slice(0, -1)}d`])
			expect(() => Task.create({ ...taskOptions, id })).toThrow();
		const raw = decodeTaskConfiguration(taskWire);
		for (const patch of [
			{ vdafType: 2 },
			{ vdafConfig: hex("00") },
			{ batchMode: 2 },
			{ batchConfig: hex("00") },
			{ extensions: [{ type: 2, data: hex("") }] },
		]) {
			expect(() =>
				Task.decode({
					id: task.id,
					configuration: encodeTaskConfiguration({ ...raw, ...patch }),
				}),
			).toThrow();
		}
	});
	it("enforces task intervals and ordered mandatory extensions", () => {
		const extensions = [
			{ type: 1, data: hex("00000000000000020000000000000003") },
		];
		const limited = Task.create({ ...taskOptions, extensions });
		expect([1n, 2n, 4n, 5n].map((time) => limited.inInterval(time))).toEqual([
			false,
			true,
			true,
			false,
		]);
		expect(() =>
			Task.create({
				...taskOptions,
				extensions: [...extensions, ...extensions],
			}),
		).toThrow();
		expect(() =>
			decodeTaskConfiguration(limited.encodeConfiguration(), {
				maxExtensions: 0,
			}),
		).toThrow();
	});
});

it("decodes HPKE lists, preserves unsupported suites, and rejects ambiguous IDs", () => {
	const encoded = encodeHpkeConfigList([
		{ ...config, id: 2, kemId: 65535 },
		config,
	]);
	const list = HpkeConfigList.parse(encoded);
	encoded.fill(0);
	list.configs[1]!.publicKey.fill(0);
	expect(list.configs[0]!.kemId).toBe(65535);
	expect(list.configs[1]!.publicKey).toEqual(config.publicKey);
	for (const value of [
		hex("0000"),
		hex("000aff"),
		new Uint8Array([...list.encode(), 0]),
	])
		expect(() => decodeHpkeConfigList(value)).toThrow();
	expect(() => encodeHpkeConfigList([config, config])).toThrow();
	for (let i = 0; i < list.encode().length; i++)
		expect(() => decodeHpkeConfigList(list.encode().slice(0, i))).toThrow();
});

it("matches a hand-derived report and concatenates reports without a bulk prefix", () => {
	const encoded = hex(
		"000102030405060708090a0b0c0d0e0f0000000000000002000000000000070001aa00000001bb080001cc00000001dd",
	);
	const report = {
		metadata: {
			id: hex("000102030405060708090a0b0c0d0e0f"),
			time: 2n,
			publicExtensions: [],
		},
		publicShare: hex(""),
		leader: { configId: 7, enc: hex("aa"), payload: hex("bb") },
		helper: { configId: 8, enc: hex("cc"), payload: hex("dd") },
	};
	expect(encodeReport(report)).toEqual(encoded);
	expect(decodeReport(encoded)).toEqual(report);
	expect(encodeUploadRequest([report, encoded])).toEqual(
		new Uint8Array([...encoded, ...encoded]),
	);
	expect(decodeUploadRequest(encodeUploadRequest([report, report]))).toEqual([
		report,
		report,
	]);
	expect(() => decodeUploadRequest(new Uint8Array())).toThrow();
	for (let i = 0; i < encoded.length; i++)
		expect(() => decodeReport(encoded.slice(0, i))).toThrow();
	expect(() => decodeReport(new Uint8Array([...encoded, 0]))).toThrow();
});

it("decodes 17-byte upload failures including future error codes", () => {
	expect(decodeUploadErrors(hex("0000000000000000000000000000000004"))).toEqual(
		[{ id: "AAAAAAAAAAAAAAAAAAAAAA", rawCode: 4 }],
	);
	expect(
		decodeUploadErrors(hex("00000000000000000000000000000000ff"))[0]!.rawCode,
	).toBe(255);
	expect(() => decodeUploadErrors(new Uint8Array(17))).toThrow();
	expect(() => decodeUploadErrors(new Uint8Array(16))).toThrow();
});

it("compares VDAF configurations structurally, not by identity", () => {
	const options = {
		id: "8BY0RzZMzxvA46_8ymhzycOB9krN-QIGYvg_RsByGec",
		leader: "https://l/",
		helper: "https://h/",
		timePrecision: 60,
		minBatchSize: 100,
		batchMode: "time-interval",
	} as const;
	const sum = Task.create({ ...options, vdaf: prio3Sum(1337) });
	// A separately constructed factory result must still match.
	expect(sum.expect(prio3Sum(1337)).vdaf.maxMeasurement).toBe(1337n);
	expect(() => sum.expect(prio3Sum(1338))).toThrow();
	expect(() => sum.expect(prio3Count())).toThrow();
	const histogram = Task.create({ ...options, vdaf: prio3Histogram(4, 2) });
	expect(histogram.expect(prio3Histogram(4, 2)).vdaf.length).toBe(4);
	expect(() => histogram.expect(prio3Histogram(4, 4))).toThrow();
	// A hand-rolled lookalike is still refused at task creation.
	expect(() =>
		Task.create({
			...options,
			vdaf: { type: "prio3-sum", maxMeasurement: 0n } as never,
		}),
	).toThrow();
});
