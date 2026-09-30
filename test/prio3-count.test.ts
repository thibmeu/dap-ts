import { Keccak } from "@noble/hashes/sha3.js";
import { describe, expect, it, vi } from "vitest";
import {
	shardCount,
	shardCountWithRandomness,
	unshardCount,
	xof,
} from "../src/prio3-count.js";

const api = { shardCount, unshardCount };

import count0 from "./vectors/Prio3Count_0.json";
import count2 from "./vectors/Prio3Count_2.json";
import xofVector from "./vectors/XofTurboShake128.json";

const bytes = (hex: string) => Uint8Array.fromHex(hex);

describe("VDAF draft 20 count vectors", () => {
	for (const [name, vector] of Object.entries({ count0, count2 })) {
		it(`${name}: sharding matches every encoded byte`, () => {
			for (const report of vector.reports) {
				const result = shardCountWithRandomness(
					report.measurement as 0 | 1,
					bytes(vector.ctx),
					bytes(report.nonce),
					bytes(report.rand),
				);
				expect(result.publicShare).toEqual(bytes(report.public_share));
				expect(result.inputShares).toEqual(report.input_shares.map(bytes));
			}
		});

		it(`${name}: unsharding matches the aggregate result`, () => {
			expect(
				api.unshardCount(
					vector.agg_shares.map(bytes) as [Uint8Array, Uint8Array],
				),
			).toBe(BigInt(vector.agg_result));
		});
	}
});

it("matches the official XOF seed and streams the published expansion", () => {
	const stream = xof(
		bytes(xofVector.seed),
		bytes(xofVector.dst),
		bytes(xofVector.binder),
	);
	try {
		expect(stream.xof(32)).toEqual(bytes(xofVector.derived_seed));
		// These particular Field128 candidates are all canonical. The first
		// 32 bytes are the same stream prefix as derived_seed.
		expect(stream.xof(xofVector.length * 16 - 32)).toEqual(
			bytes(xofVector.expanded_vec_field128).subarray(32),
		);
	} finally {
		stream.destroy();
	}
});

it("uses fresh randomness on every public call", () => {
	const report = count0.reports[0]!;
	const first = api.shardCount(1, bytes(count0.ctx), bytes(report.nonce));
	const second = api.shardCount(1, bytes(count0.ctx), bytes(report.nonce));
	expect(first.inputShares).not.toEqual(second.inputShares);
});

it("discards an out-of-field XOF candidate rather than reducing it", () => {
	const mock = vi
		.spyOn(Keccak.prototype, "xofInto")
		.mockImplementationOnce((output) => output.fill(255));
	try {
		const report = count0.reports[0]!;
		const result = shardCountWithRandomness(
			1,
			bytes(count0.ctx),
			bytes(report.nonce),
			bytes(report.rand),
		);
		expect(result.inputShares).toEqual(report.input_shares.map(bytes));
	} finally {
		mock.mockRestore();
	}
});

it("binds shares to the context and leaves caller buffers unchanged", () => {
	const report = count0.reports[0]!;
	const rand = bytes(report.rand);
	const nonce = bytes(report.nonce);
	const first = shardCountWithRandomness(1, bytes(count0.ctx), nonce, rand);
	const second = shardCountWithRandomness(1, new Uint8Array(), nonce, rand);
	expect(first.inputShares[0]).not.toEqual(second.inputShares[0]);
	first.inputShares[1].fill(0);
	expect(rand).toEqual(bytes(report.rand));
	expect(nonce).toEqual(bytes(report.nonce));
});

it("rejects invalid measurements and input lengths", () => {
	for (const value of [-1, 2, 0.5, NaN, Infinity, true, "1"]) {
		expect(() =>
			shardCountWithRandomness(
				value as 0,
				new Uint8Array(),
				new Uint8Array(16),
				new Uint8Array(64),
			),
		).toThrow();
	}
	for (const length of [0, 15, 17]) {
		expect(() =>
			shardCountWithRandomness(
				1,
				new Uint8Array(),
				new Uint8Array(length),
				new Uint8Array(64),
			),
		).toThrow();
	}
	for (const length of [0, 63, 65]) {
		expect(() =>
			shardCountWithRandomness(
				1,
				new Uint8Array(),
				new Uint8Array(16),
				new Uint8Array(length),
			),
		).toThrow();
	}
	expect(() =>
		shardCountWithRandomness(
			1,
			new Uint8Array(65528),
			new Uint8Array(16),
			new Uint8Array(64),
		),
	).toThrow();
	expect(() =>
		xof(new Uint8Array(256), new Uint8Array(), new Uint8Array()),
	).toThrow();
	expect(() =>
		xof(new Uint8Array(), new Uint8Array(65536), new Uint8Array()),
	).toThrow();
});

it("rejects malformed aggregate shares without reducing non-canonical values", () => {
	for (const value of [
		"",
		"00000000000000",
		"000000000000000000",
		"01000000ffffffff",
		"ffffffffffffffff",
	]) {
		expect(() => api.unshardCount([bytes(value), new Uint8Array(8)])).toThrow();
	}
	expect(() =>
		api.unshardCount([] as unknown as [Uint8Array, Uint8Array]),
	).toThrow();
});

it("preserves large counts and respects typed-array offsets", () => {
	const padded = bytes("ff0100000000002000ff");
	expect(api.unshardCount([padded.subarray(1, 9), new Uint8Array(8)])).toBe(
		9007199254740993n,
	);
	expect(
		api.unshardCount([bytes("00000000ffffffff"), bytes("0100000000000000")]),
	).toBe(0n);
});
