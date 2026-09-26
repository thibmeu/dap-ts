import { beforeAll, describe, expect, it, vi } from "vitest";
import { concat, decodeId, Reader } from "../src/binary.js";
import { createSuite } from "../src/hpke.js";
import {
	DAPClient,
	DAPError,
	HpkeConfigList,
	prio3Sum,
	Task,
} from "../src/index.js";
import {
	decodeReport,
	encodeHpkeConfigList,
	encodeInputShareAad,
	encodeReport,
} from "../src/messages.js";
import { shardCountWithRandomness } from "../src/prio3-count.js";
import { shardSumWithRandomness } from "../src/prio3-sum.js";
import {
	config,
	deterministicRandom,
	hex,
	hpke,
	task,
	taskOptions,
	text,
} from "./fixtures.js";
import vector from "./vectors/hpke-rfc9180-a1.json";

const suite = createSuite();
let privateKey: CryptoKey;
beforeAll(async () => {
	privateKey = await suite.DeserializePrivateKey(hex(vector.skRm));
});

it("matches RFC 9180 Appendix A.1.1, including the deterministic encapsulation", async () => {
	const sender = createSuite(() => hex(vector.ikmE));
	const publicKey = await sender.DeserializePublicKey(hex(vector.pkRm));
	const result = await sender.Seal(publicKey, hex(vector.pt), {
		info: hex(vector.info),
		aad: hex(vector.aad),
	});
	expect(result.encapsulatedSecret).toEqual(hex(vector.enc));
	expect(result.ciphertext).toEqual(hex(vector.ct));
});

it("prepares an encrypted count report with the exact DAP task/role binding", async () => {
	const client = new DAPClient(task, {
		hpke,
		random: deterministicRandom(),
		clock: () => 179999,
	});
	const prepared = await client.prepareReport(1);
	expect(prepared.time).toBe(2);
	expect(Object.keys(prepared).sort()).toEqual(["id", "time"]);
	const report = decodeReport(encodeReport(prepared));
	expect(report.metadata.id).toEqual(
		Uint8Array.from({ length: 16 }, (_, i) => i),
	);
	const taskId = decodeId(task.id, 32);
	const aad = encodeInputShareAad(
		taskId,
		task.encodeConfiguration(),
		report.metadata,
		report.publicShare,
	);
	const expected = shardCountWithRandomness(
		1,
		concat(text("dap-19"), taskId),
		report.metadata.id,
		Uint8Array.from({ length: 64 }, (_, i) => i + 16),
	);
	for (const [i, ciphertext] of [report.leader, report.helper].entries()) {
		const info = concat(text("dap-19 input share"), Uint8Array.of(1, i + 2));
		const plaintext = await suite.Open(
			privateKey,
			ciphertext.enc,
			ciphertext.payload,
			{ aad, info },
		);
		const reader = new Reader(plaintext);
		expect(reader.vector(2)).toEqual(new Uint8Array());
		expect(reader.vector(4)).toEqual(expected.inputShares[i]);
		reader.end();
		await expect(
			suite.Open(privateKey, ciphertext.enc, ciphertext.payload, {
				aad,
				info: concat(
					text("dap-19 input share"),
					Uint8Array.of(1, i === 0 ? 3 : 2),
				),
			}),
		).rejects.toThrow();
		const changed = aad.slice();
		changed[0] ^= 1;
		await expect(
			suite.Open(privateKey, ciphertext.enc, ciphertext.payload, {
				aad: changed,
				info,
			}),
		).rejects.toThrow();
	}
	const same = await new DAPClient(task, {
		hpke,
		random: deterministicRandom(),
		clock: () => 179999,
	}).prepareReport(1);
	expect(encodeReport(same)).toEqual(encodeReport(prepared));
});

it("round-trips a bounded sum task and encrypts its published VDAF shares", async () => {
	const sumTask = Task.create({ ...taskOptions, vdaf: prio3Sum(1337) });
	expect(sumTask.encodeConfiguration()).toEqual(
		Task.decode({
			id: sumTask.id,
			configuration: sumTask.encodeConfiguration(),
		})
			.expect(prio3Sum(1337))
			.encodeConfiguration(),
	);
	expect(() =>
		Task.decode({
			id: sumTask.id,
			configuration: sumTask.encodeConfiguration(),
		}).expect(prio3Sum(255)),
	).toThrow();
	const client = new DAPClient(sumTask, {
		hpke,
		random: deterministicRandom(),
		clock: () => 179999,
	});
	for (const invalid of [-1, 1338, 0.5, Number.MAX_SAFE_INTEGER + 1]) {
		await expect(client.prepareReport(invalid)).rejects.toMatchObject({
			code: "InvalidMeasurement",
		});
	}
	const prepared = await client.prepareReport(1337);
	const report = decodeReport(encodeReport(prepared));
	const taskId = decodeId(sumTask.id, 32);
	const expected = shardSumWithRandomness(
		1337,
		1337,
		concat(text("dap-19"), taskId),
		report.metadata.id,
		Uint8Array.from({ length: 64 }, (_, i) => i + 16),
	);
	const aad = encodeInputShareAad(
		taskId,
		sumTask.encodeConfiguration(),
		report.metadata,
		report.publicShare,
	);
	for (const [i, ciphertext] of [report.leader, report.helper].entries()) {
		const plaintext = await suite.Open(
			privateKey,
			ciphertext.enc,
			ciphertext.payload,
			{
				info: concat(text("dap-19 input share"), Uint8Array.of(1, i + 2)),
				aad,
			},
		);
		const reader = new Reader(plaintext);
		expect(reader.vector(2)).toEqual(new Uint8Array());
		expect(reader.vector(4)).toEqual(expected.inputShares[i]);
		reader.end();
	}
});

it("snapshots extensions before encryption and detects duplicate scopes", async () => {
	const client = new DAPClient(task, { hpke });
	const data = hex("0102");
	const extensions = [{ type: 100, data }];
	const pending = client.prepareReport(0, { publicExtensions: extensions });
	data.fill(255);
	extensions[0]!.type = 101;
	const report = decodeReport(encodeReport(await pending));
	expect(report.metadata.publicExtensions).toEqual([
		{ type: 100, data: hex("0102") },
	]);
	const aad = encodeInputShareAad(
		decodeId(task.id, 32),
		task.encodeConfiguration(),
		report.metadata,
		report.publicShare,
	);
	await expect(
		suite.Open(privateKey, report.leader.enc, report.leader.payload, {
			aad,
			info: concat(text("dap-19 input share"), Uint8Array.of(1, 2)),
		}),
	).resolves.toBeInstanceOf(Uint8Array);
	await expect(
		client.prepareReport(1, {
			publicExtensions: extensions,
			privateExtensions: { leader: extensions },
		}),
	).rejects.toMatchObject({ code: "InvalidReport" });
});

it("rejects unsupported HPKE suites early and rotates keys explicitly", async () => {
	const unsupported = HpkeConfigList.parse(
		encodeHpkeConfigList([{ ...config, kemId: 65535 }]),
	);
	expect(
		() =>
			new DAPClient(task, {
				hpke: { leader: unsupported, helper: hpke.helper },
			}),
	).toThrow(DAPError);
	const mixed = HpkeConfigList.parse(
		encodeHpkeConfigList([{ ...config, id: 1, kemId: 65535 }, config]),
	);
	const client = new DAPClient(task, {
		hpke: { leader: mixed, helper: hpke.helper },
	});
	const old = await client.prepareReport(1);
	const rotated = HpkeConfigList.parse(
		encodeHpkeConfigList([{ ...config, id: 9 }]),
	);
	const next = client.withHpkeConfigs({ leader: rotated, helper: rotated });
	expect(
		decodeReport(encodeReport(await next.prepareReport(1))).leader.configId,
	).toBe(9);
	expect(
		decodeReport(encodeReport(await client.prepareReport(1))).leader.configId,
	).toBe(7);
	expect(next.prepareUpload([old]).request.body).toEqual(encodeReport(old));
});

it("validates measurement, time, and random-source inputs", async () => {
	const client = new DAPClient(task, { hpke });
	for (const measurement of [2, -1, NaN, 0.5, true, "1"])
		await expect(
			client.prepareReport(measurement as number),
		).rejects.toMatchObject({ code: "InvalidMeasurement" });
	for (const time of [-1, NaN, Infinity, 1.2, new Date(NaN)])
		await expect(client.prepareReport(1, { time })).rejects.toThrow();
	await expect(
		new DAPClient(task, {
			hpke,
			random: () => new Uint8Array(1),
		}).prepareReport(1),
	).rejects.toThrow();
	expect((await client.prepareReport(1, { time: new Date(60000) })).time).toBe(
		1,
	);
});

describe("bulk uploads", () => {
	it("owns report bytes, binds tasks, and reuses report IDs for retries", async () => {
		const client = new DAPClient(task, { hpke });
		const reports = await client.prepareReports([1, 0, 1]);
		const upload = client.prepareUpload(reports);
		const first = upload.request.body!.slice();
		upload.request.body!.fill(0);
		encodeReport(reports[0]!).fill(0);
		expect(upload.request.body).toEqual(first);
		expect(upload.request.url).toBe(`https://l/tasks/${task.id}/reports`);
		expect(() => client.prepareUpload([reports[0]!, reports[0]!])).toThrow();
		expect(() => client.prepareUpload([])).toThrow();
		expect(() =>
			client.prepareUpload([{ id: reports[0]!.id, time: 0 } as never]),
		).toThrow();
		const other = new DAPClient(
			Task.create({ ...taskOptions, info: "other" }),
			{ hpke },
		);
		expect(() => other.prepareUpload(reports)).toThrow();
	});
	it("processes partial failures in submission order and preserves unknown codes", async () => {
		const client = new DAPClient(task, { hpke });
		const reports = await client.prepareReports([1, 0, 1]);
		const upload = client.prepareUpload(reports);
		const status = (i: number, code: number) =>
			concat(decodeId(reports[i]!.id, 16), Uint8Array.of(code));
		const headers = {
			"Content-Type": 'Application/PPM-DAP; message="upload-errors";version=19',
		};
		expect(upload.process({ status: 204, headers: {}, body: hex("") })).toEqual(
			{ accepted: reports.map((r) => r.id), rejected: [], ok: true },
		);
		const partial = upload.process({
			status: 200,
			headers,
			body: concat(status(0, 4), status(2, 255)),
		});
		expect(partial.accepted).toEqual([reports[1]!.id]);
		expect(partial.rejected.map((r) => [r.code, r.rawCode])).toEqual([
			["hpke-unknown-config-id", 4],
			["unknown", 255],
		]);
		expect(partial.ok).toBe(false);
		for (const body of [
			concat(status(2, 4), status(0, 4)),
			concat(status(0, 4), status(0, 4)),
			new Uint8Array(16),
			status(0, 0),
			concat(new Uint8Array(16).fill(255), Uint8Array.of(4)),
		]) {
			expect(() => upload.process({ status: 200, headers, body })).toThrow(
				DAPError,
			);
		}
		for (const contentType of [
			"application/json",
			"application/ppm-dap;message=report",
			"application/ppm-dap;message=upload-errors;version=09",
			"application/ppm-dap;message=upload-errors;message=upload-errors",
		]) {
			expect(() =>
				upload.process({
					status: 200,
					headers: { "content-type": contentType },
					body: status(0, 4),
				}),
			).toThrow();
		}
		expect(() =>
			upload.process({
				status: 400,
				headers: { "content-type": "application/problem+json" },
				body: text('{"type":"urn:ietf:params:ppm:dap:error:unrecognizedTask"}'),
			}),
		).toThrow(DAPError);
	});
	it("bounds concurrency and preserves measurement order", async () => {
		const client = new DAPClient(task, { hpke });
		const original = DAPClient.prototype.prepareReport;
		let active = 0,
			maximum = 0;
		const spy = vi
			.spyOn(DAPClient.prototype, "prepareReport")
			.mockImplementation(async function (measurement, options) {
				active++;
				maximum = Math.max(maximum, active);
				try {
					return await original.call(this, measurement, options);
				} finally {
					active--;
				}
			});
		try {
			const reports = await client.prepareReports([1, 0, 1, 0, 1], {
				concurrency: 2,
			});
			expect(reports).toHaveLength(5);
			expect(maximum).toBe(2);
			expect(new Set(reports.map((r) => r.id)).size).toBe(5);
			await expect(
				client.prepareReports([1], { concurrency: 0 }),
			).rejects.toThrow();
		} finally {
			spy.mockRestore();
		}
	});
});
