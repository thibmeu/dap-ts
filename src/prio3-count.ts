import { turboshake128 } from "@noble/hashes/sha3-addons.js";

// VDAF draft 20, Sections 6.1.4 and 7.4.1.
export const P = 0xffff_ffff_0000_0001n;
const HALF = (P + 1n) / 2n;
// 7^((P - 1) / 4) mod P, the specified principal fourth root of unity.
const ROOT4 = 281474976710656n;

export function mod(value: bigint): bigint {
	const remainder = value % P;
	return remainder < 0n ? remainder + P : remainder;
}

export function requireBytes(value: Uint8Array, length?: number): void {
	if (!(value instanceof Uint8Array)) throw new TypeError("Expected bytes");
	if (length !== undefined && value.length !== length) {
		throw new RangeError(`Expected ${length} bytes`);
	}
}

// Internal exports let tests supply vectors without exposing deterministic
// randomness or XOF plumbing through the package entry point.
export function xof(seed: Uint8Array, dst: Uint8Array, binder: Uint8Array) {
	requireBytes(seed);
	requireBytes(dst);
	requireBytes(binder);
	if (seed.length > 255 || dst.length > 65535) {
		throw new RangeError("XOF seed or domain separation tag is too long");
	}
	return turboshake128
		.create({ D: 1 })
		.update(Uint8Array.of(dst.length & 255, dst.length >>> 8))
		.update(dst)
		.update(Uint8Array.of(seed.length))
		.update(seed)
		.update(binder);
}

export function expand(
	seed: Uint8Array,
	ctx: Uint8Array,
	usage: number,
	binder: Uint8Array,
	length: number,
	vdafId = 1,
	modulus = P,
	fieldWidth = 8,
): bigint[] {
	// Draft 20 retains VERSION=18. Class=0; the VDAF ID separates variants.
	const dst = new Uint8Array(8 + ctx.length);
	dst.set([18, 0, 0, 0, 0, vdafId, 0, usage]);
	dst.set(ctx, 8);
	const stream = xof(seed, dst, binder);
	const bytes = new Uint8Array(fieldWidth);
	const view = new DataView(bytes.buffer);
	const elements: bigint[] = [];
	try {
		while (elements.length < length) {
			stream.xofInto(bytes);
			let value: bigint;
			if (fieldWidth === 8) value = view.getBigUint64(0, true);
			else {
				value = 0n;
				for (let i = fieldWidth - 1; i >= 0; i--)
					value = (value << 8n) | BigInt(bytes[i]!);
			}
			if (value < modulus) elements.push(value);
		}
		return elements;
	} finally {
		stream.destroy();
	}
}

/** Shard a count measurement for two aggregators using fresh random bytes. */
export function shardCount(
	measurement: number,
	ctx: Uint8Array,
	nonce: Uint8Array,
): { publicShare: Uint8Array; inputShares: [Uint8Array, Uint8Array] } {
	const rand = crypto.getRandomValues(new Uint8Array(64));
	try {
		return shardCountWithRandomness(measurement, ctx, nonce, rand);
	} finally {
		rand.fill(0);
	}
}

export function shardCountWithRandomness(
	measurement: number,
	ctx: Uint8Array,
	nonce: Uint8Array,
	rand: Uint8Array,
): { publicShare: Uint8Array; inputShares: [Uint8Array, Uint8Array] } {
	if (measurement !== 0 && measurement !== 1) {
		throw new RangeError("Count measurement must be 0 or 1");
	}
	requireBytes(ctx);
	requireBytes(nonce, 16);
	requireBytes(rand, 64);
	if (ctx.length > 65527) throw new RangeError("Context is too long");

	const helper = rand.slice(0, 32);
	const [helperMeasurement] = expand(helper, ctx, 1, Uint8Array.of(1), 1);
	const helperProof = expand(helper, ctx, 2, Uint8Array.of(1, 1), 5);
	const [a, b] = expand(rand.subarray(32), ctx, 4, Uint8Array.of(1), 2);
	const m = BigInt(measurement);

	// Count has one multiplication, x*x. Its two linear wire polynomials
	// interpolate (1, seed) and (-1, m). The proof stores their seeds and
	// their product evaluated at 1, ROOT4, and -1 (Sections 7.3.3, 7.4.1).
	// This fixed calculation avoids an NTT implementation for a single gate.
	const wireA = mod((a! + m + (a! - m) * ROOT4) * HALF);
	const wireB = mod((b! + m + (b! - m) * ROOT4) * HALF);
	const proof = [a!, b!, mod(a! * b!), mod(wireA * wireB), m];
	const leader = new Uint8Array(48);
	const view = new DataView(leader.buffer);
	view.setBigUint64(0, mod(m - helperMeasurement!), true);
	for (let i = 0; i < proof.length; i++) {
		view.setBigUint64(8 * (i + 1), mod(proof[i]! - helperProof[i]!), true);
	}
	return { publicShare: new Uint8Array(), inputShares: [leader, helper] };
}

/** Combine two already authenticated aggregate shares into an exact count. */
export function unshardCount(
	shares: readonly [Uint8Array, Uint8Array],
): bigint {
	if (!Array.isArray(shares) || shares.length !== 2) {
		throw new RangeError("Expected two aggregate shares");
	}
	let total = 0n;
	for (const share of shares) {
		requireBytes(share, 8);
		const value = new DataView(
			share.buffer,
			share.byteOffset,
			share.byteLength,
		).getBigUint64(0, true);
		if (value >= P) throw new RangeError("Non-canonical Field64 element");
		total = (total + value) % P;
	}
	return total;
}
