import { describe, expect, it } from "vitest";
import {
	shardHistogramWithRandomness,
	unshardHistogram,
} from "../src/prio3-histogram.js";
import { prio3Histogram } from "../src/vdaf.js";
import histogram0 from "./vectors/Prio3Histogram_0.json";
import histogram2 from "./vectors/Prio3Histogram_2.json";

const bytes = (hex: string) => Uint8Array.fromHex(hex);

describe("VDAF draft 20 Prio3Histogram", () => {
	for (const [name, vector] of Object.entries({ histogram0, histogram2 })) {
		it(`${name}: matches published two-aggregator shares`, () => {
			for (const report of vector.reports) {
				const result = shardHistogramWithRandomness(
					report.measurement,
					vector.length,
					vector.chunk_length,
					bytes(vector.ctx),
					bytes(report.nonce),
					bytes(report.rand),
				);
				expect(result.publicShare).toEqual(bytes(report.public_share));
				expect(result.inputShares).toEqual(report.input_shares.map(bytes));
			}
		});
		it(`${name}: combines published aggregate shares`, () => {
			expect(
				unshardHistogram(
					vector.agg_shares.map(bytes) as [Uint8Array, Uint8Array],
					vector.length,
				),
			).toEqual(vector.agg_result.map(BigInt));
		});
	}
});

it("rejects invalid histogram parameters and buckets", () => {
	for (const length of [0, -1, 4097, 1.5])
		expect(() => prio3Histogram(length, 2)).toThrow();
	const args = [
		4,
		2,
		new Uint8Array(),
		new Uint8Array(16),
		new Uint8Array(128),
	] as const;
	for (const bucket of [-1, 4, 1.5, Number.MAX_SAFE_INTEGER + 1])
		expect(() => shardHistogramWithRandomness(bucket, ...args)).toThrow();
});
