import { describe, expect, it } from "vitest";
import { P } from "../src/prio3-count.js";
import { shardSumWithRandomness, unshardSum } from "../src/prio3-sum.js";
import { prio3Sum } from "../src/vdaf.js";
import sum0 from "./vectors/Prio3Sum_0.json";
import sum2 from "./vectors/Prio3Sum_2.json";

const bytes = (hex: string) => Uint8Array.fromHex(hex);

describe("VDAF draft 20 Prio3Sum", () => {
	for (const [name, vector] of Object.entries({ sum0, sum2 })) {
		it(`${name}: matches published two-aggregator shares`, () => {
			for (const report of vector.reports) {
				const result = shardSumWithRandomness(
					report.measurement,
					vector.max_measurement,
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
				unshardSum(vector.agg_shares.map(bytes) as [Uint8Array, Uint8Array]),
			).toBe(BigInt(vector.agg_result));
		});
	}
});

it("validates full Field64 bounds and rejects invalid measurements", () => {
	for (const bound of [0, -1, P, 0.5, Number.MAX_SAFE_INTEGER + 1]) {
		expect(() => prio3Sum(bound)).toThrow();
	}
	expect(prio3Sum(P - 1n).maxMeasurement).toBe(P - 1n);
	const args = [
		new Uint8Array(),
		new Uint8Array(16),
		new Uint8Array(64),
	] as const;
	for (const value of [-1, 1338, 0.5, Number.MAX_SAFE_INTEGER + 1, "1"]) {
		expect(() =>
			shardSumWithRandomness(value as number, 1337, ...args),
		).toThrow();
	}
});
