import { concat, Reader, uint } from "./binary.js";
import { shardCountWithRandomness, unshardCount } from "./prio3-count.js";
import {
	checkHistogram,
	shardHistogramWithRandomness,
	unshardHistogram,
	validateHistogramMeasurement,
} from "./prio3-histogram.js";
import {
	shardSumWithRandomness,
	sumBound,
	unshardSum,
	validateSumMeasurement,
} from "./prio3-sum.js";

export interface Prio3Count {
	readonly type: "prio3-count";
}
export interface Prio3Sum {
	readonly type: "prio3-sum";
	readonly maxMeasurement: bigint;
}
export interface Prio3Histogram {
	readonly type: "prio3-histogram";
	readonly length: number;
	readonly chunkLength: number;
}
export type Vdaf = Prio3Count | Prio3Sum | Prio3Histogram;

/** What a Client reports for a VDAF. */
export type Measurement<V extends Vdaf> = V extends Prio3Count
	? 0 | 1
	: V extends Prio3Sum
		? number | bigint
		: number;
/** What a Collector receives for a VDAF. */
export type AggregateResult<V extends Vdaf> = V extends Prio3Histogram
	? readonly bigint[]
	: bigint;

/** Prio3Count reports 0 or 1 and aggregates to the number of 1s. */
export function prio3Count(): Prio3Count {
	return Object.freeze({ type: "prio3-count" });
}

/** Prio3Sum reports an integer from zero through maxMeasurement. */
export function prio3Sum(maxMeasurement: number | bigint): Prio3Sum {
	return Object.freeze({
		type: "prio3-sum",
		maxMeasurement: sumBound(maxMeasurement),
	});
}

/** Prio3Histogram reports one bucket index from 0 through length - 1. */
export function prio3Histogram(
	length: number,
	chunkLength: number,
): Prio3Histogram {
	checkHistogram(length, chunkLength);
	return Object.freeze({ type: "prio3-histogram", length, chunkLength });
}

/** Re-run the factory so a hand-built object gets the same range checks. */
export function checkVdaf(vdaf: Vdaf): Vdaf {
	switch (vdaf?.type) {
		case "prio3-count":
			return prio3Count();
		case "prio3-sum":
			return prio3Sum(vdaf.maxMeasurement);
		case "prio3-histogram":
			return prio3Histogram(vdaf.length, vdaf.chunkLength);
		default:
			throw new RangeError("Use a built-in VDAF factory");
	}
}

export function sameVdaf(a: Vdaf, b: Vdaf): boolean {
	const x = encodeVdaf(a);
	const y = encodeVdaf(b);
	return x.type === y.type && x.config.every((byte, i) => byte === y.config[i]);
}

/** VDAF type and configuration as carried in TaskConfiguration (DAP 19, 4.2). */
export function encodeVdaf(vdaf: Vdaf): { type: number; config: Uint8Array } {
	switch (vdaf.type) {
		case "prio3-count":
			return { type: 1, config: new Uint8Array() };
		case "prio3-sum":
			return { type: 2, config: uint(vdaf.maxMeasurement, 8) };
		case "prio3-histogram":
			return {
				type: 4,
				config: concat(uint(vdaf.length, 4), uint(vdaf.chunkLength, 4)),
			};
	}
}

export function decodeVdaf(type: number, config: Uint8Array): Vdaf | undefined {
	if (type === 1 && !config.length) return prio3Count();
	if (config.length !== 8) return undefined;
	const reader = new Reader(config);
	if (type === 2) return prio3Sum(reader.u64());
	if (type === 4) return prio3Histogram(reader.uint(4), reader.uint(4));
	return undefined;
}

/** Throw RangeError or TypeError when a measurement is not valid for the VDAF. */
export function validateMeasurement(vdaf: Vdaf, measurement: unknown): void {
	switch (vdaf.type) {
		case "prio3-count":
			if (measurement !== 0 && measurement !== 1)
				throw new RangeError("Count measurement must be 0 or 1");
			return;
		case "prio3-sum":
			validateSumMeasurement(
				measurement as number | bigint,
				vdaf.maxMeasurement,
			);
			return;
		case "prio3-histogram":
			validateHistogramMeasurement(measurement as number, vdaf.length);
	}
}

/** Bytes of randomness sharding consumes. */
export function randomLength(vdaf: Vdaf): number {
	return vdaf.type === "prio3-histogram" ? 128 : 64;
}

export function shard(
	vdaf: Vdaf,
	measurement: unknown,
	ctx: Uint8Array,
	nonce: Uint8Array,
	rand: Uint8Array,
): { publicShare: Uint8Array; inputShares: [Uint8Array, Uint8Array] } {
	switch (vdaf.type) {
		case "prio3-count":
			return shardCountWithRandomness(measurement as number, ctx, nonce, rand);
		case "prio3-sum":
			return shardSumWithRandomness(
				measurement as number | bigint,
				vdaf.maxMeasurement,
				ctx,
				nonce,
				rand,
			);
		case "prio3-histogram":
			return shardHistogramWithRandomness(
				measurement as number,
				vdaf.length,
				vdaf.chunkLength,
				ctx,
				nonce,
				rand,
			);
	}
}

/** Bytes in one output or aggregate share. */
export function shareLength(vdaf: Vdaf): number {
	return vdaf.type === "prio3-histogram" ? vdaf.length * 16 : 8;
}

/**
 * Combine the two aggregate shares and check the result could come from
 * reportCount valid measurements.
 */
export function unshard(
	vdaf: Vdaf,
	shares: readonly [Uint8Array, Uint8Array],
	reportCount: bigint,
): bigint | bigint[] {
	switch (vdaf.type) {
		case "prio3-count":
		case "prio3-sum": {
			const value = (vdaf.type === "prio3-count" ? unshardCount : unshardSum)(
				shares,
			);
			const bound = vdaf.type === "prio3-count" ? 1n : vdaf.maxMeasurement;
			if (value > reportCount * bound)
				throw new RangeError("Aggregate exceeds the measurement bound");
			return value;
		}
		case "prio3-histogram": {
			const value = unshardHistogram(shares, vdaf.length);
			if (value.reduce((sum, bucket) => sum + bucket, 0n) !== reportCount)
				throw new RangeError("Histogram total does not match the report count");
			return value;
		}
	}
}
