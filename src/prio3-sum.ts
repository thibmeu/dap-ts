import {
	type ClientVdaf,
	expand,
	mod,
	P,
	requireBytes,
	unshardCount,
} from "./prio3-count.js";

const sumVdafs = new Map<bigint, ClientVdaf<number | bigint>>();

function integer(value: number | bigint): bigint {
	if (typeof value === "bigint") return value;
	if (!Number.isSafeInteger(value))
		throw new RangeError("Expected a safe integer or bigint");
	return BigInt(value);
}

/** Prio3Sum accepts integers from zero through maxMeasurement. */
export function prio3Sum(
	maxMeasurement: number | bigint,
): ClientVdaf<number | bigint> {
	const max = integer(maxMeasurement);
	if (max <= 0n || max >= P) throw new RangeError("Invalid sum bound");
	let vdaf = sumVdafs.get(max);
	if (!vdaf) {
		vdaf = Object.freeze({
			type: "prio3-sum",
			maxMeasurement: max,
		}) as ClientVdaf<number | bigint>;
		sumVdafs.set(max, vdaf);
	}
	return vdaf;
}

function power(base: bigint, exponent: bigint): bigint {
	let result = 1n;
	while (exponent) {
		if (exponent & 1n) result = mod(result * base);
		base = mod(base * base);
		exponent >>= 1n;
	}
	return result;
}

// The Field64 transform evaluates at successive powers of its principal root.
function transform(values: bigint[], size: number, inverse = false): bigint[] {
	const out = Array<bigint>(size).fill(0n);
	for (let i = 0; i < values.length; i++) out[i] = values[i]!;
	for (let i = 1, j = 0; i < size; i++) {
		let bit = size >> 1;
		for (; j & bit; bit >>= 1) j ^= bit;
		j ^= bit;
		if (i < j) [out[i], out[j]] = [out[j]!, out[i]!];
	}
	for (let width = 2; width <= size; width *= 2) {
		const root = power(7n, (P - 1n) / BigInt(width));
		const step = inverse ? power(root, P - 2n) : root;
		for (let start = 0; start < size; start += width) {
			let factor = 1n;
			for (let j = 0; j < width / 2; j++) {
				const a = out[start + j]!;
				const b = mod(out[start + j + width / 2]! * factor);
				out[start + j] = mod(a + b);
				out[start + j + width / 2] = mod(a - b);
				factor = mod(factor * step);
			}
		}
	}
	if (inverse) {
		const scale = power(BigInt(size), P - 2n);
		for (let i = 0; i < size; i++) out[i] = mod(out[i]! * scale);
	}
	return out;
}

function encodeMeasurement(value: bigint, max: bigint): bigint[] {
	if (value < 0n || value > max)
		throw new RangeError("Sum measurement is outside its bound");
	const bits = max.toString(2).length;
	const lowerMax = (1n << BigInt(bits - 1)) - 1n;
	const lastWeight = max - lowerMax;
	const last = value > lowerMax ? 1n : 0n;
	const rest = value - last * lastWeight;
	return [
		...Array.from({ length: bits - 1 }, (_, i) => (rest >> BigInt(i)) & 1n),
		last,
	];
}

export function validateSumMeasurement(
	value: number | bigint,
	max: bigint,
): void {
	encodeMeasurement(integer(value), max);
}

export function shardSumWithRandomness(
	measurement: number | bigint,
	maxMeasurement: number | bigint,
	ctx: Uint8Array,
	nonce: Uint8Array,
	rand: Uint8Array,
): { publicShare: Uint8Array; inputShares: [Uint8Array, Uint8Array] } {
	const max = integer(maxMeasurement);
	if (max <= 0n || max >= P) throw new RangeError("Invalid sum bound");
	const meas = encodeMeasurement(integer(measurement), max);
	requireBytes(ctx);
	requireBytes(nonce, 16);
	requireBytes(rand, 64);
	if (ctx.length > 65527) throw new RangeError("Context is too long");
	let wireLength = 1;
	while (wireLength <= meas.length) wireLength *= 2;
	const proofLength = 2 * wireLength;
	const helper = rand.slice(0, 32);
	const helperMeas = expand(helper, ctx, 1, Uint8Array.of(1), meas.length, 2);
	const helperProof = expand(
		helper,
		ctx,
		2,
		Uint8Array.of(1, 1),
		proofLength,
		2,
	);
	const [seed] = expand(rand.subarray(32), ctx, 4, Uint8Array.of(1), 1, 2);
	const wire = [
		seed!,
		...meas,
		...Array<bigint>(wireLength - meas.length - 1).fill(0n),
	];
	const polynomial = transform(wire, wireLength, true);
	const evaluations = transform(polynomial, wireLength * 2);
	const proof = [
		seed!,
		...evaluations.slice(0, proofLength - 1).map((x) => mod(x * x - x)),
	];
	const leader = new Uint8Array(8 * (meas.length + proofLength));
	const view = new DataView(leader.buffer);
	for (let i = 0; i < meas.length; i++)
		view.setBigUint64(i * 8, mod(meas[i]! - helperMeas[i]!), true);
	for (let i = 0; i < proofLength; i++)
		view.setBigUint64(
			(meas.length + i) * 8,
			mod(proof[i]! - helperProof[i]!),
			true,
		);
	return { publicShare: new Uint8Array(), inputShares: [leader, helper] };
}

export function shardSum(
	measurement: number | bigint,
	maxMeasurement: number | bigint,
	ctx: Uint8Array,
	nonce: Uint8Array,
): { publicShare: Uint8Array; inputShares: [Uint8Array, Uint8Array] } {
	const rand = crypto.getRandomValues(new Uint8Array(64));
	try {
		return shardSumWithRandomness(
			measurement,
			maxMeasurement,
			ctx,
			nonce,
			rand,
		);
	} finally {
		rand.fill(0);
	}
}

export const unshardSum = unshardCount;
