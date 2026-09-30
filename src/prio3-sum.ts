import { transform } from "./field.js";
import { expand, mod, P, requireBytes, unshardCount } from "./prio3-count.js";

function integer(value: number | bigint): bigint {
	if (typeof value === "bigint") return value;
	if (!Number.isSafeInteger(value))
		throw new RangeError("Expected a safe integer or bigint");
	return BigInt(value);
}

/** Normalize a Prio3Sum bound, which must fit below the Field64 modulus. */
export function sumBound(maxMeasurement: number | bigint): bigint {
	const max = integer(maxMeasurement);
	if (max <= 0n || max >= P) throw new RangeError("Invalid sum bound");
	return max;
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
	const max = sumBound(maxMeasurement);
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
	const polynomial = transform(wire, wireLength, P, true);
	const evaluations = transform(polynomial, wireLength * 2, P);
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
