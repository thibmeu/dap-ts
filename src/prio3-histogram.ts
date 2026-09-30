import { fieldMod, transform } from "./field.js";
import { expand, requireBytes, xof } from "./prio3-count.js";

// VDAF draft 20, Sections 6.1.4, 7.2, and 7.4.4.
export const P128 = (1n << 66n) * 4611686018427387897n + 1n;
/** Check the one-hot histogram parameters this package supports. */
export function checkHistogram(length: number, chunkLength: number): void {
	if (
		!Number.isSafeInteger(length) ||
		length < 1 ||
		length > 4096 ||
		!Number.isSafeInteger(chunkLength) ||
		chunkLength < 1 ||
		chunkLength > 4096
	)
		throw new RangeError(
			"Histogram length or chunk length is outside the supported range",
		);
}

export function validateHistogramMeasurement(
	measurement: number,
	length: number,
): void {
	if (
		!Number.isSafeInteger(measurement) ||
		measurement < 0 ||
		measurement >= length
	)
		throw new RangeError("Histogram bucket is outside its range");
}

function encodeField(elements: readonly bigint[]): Uint8Array {
	const bytes = new Uint8Array(16 * elements.length);
	const view = new DataView(bytes.buffer);
	for (let i = 0; i < elements.length; i++) {
		view.setBigUint64(i * 16, elements[i]! & 0xffff_ffff_ffff_ffffn, true);
		view.setBigUint64(i * 16 + 8, elements[i]! >> 64n, true);
	}
	return bytes;
}

function deriveSeed(
	seed: Uint8Array,
	ctx: Uint8Array,
	usage: number,
	binder: Uint8Array,
): Uint8Array {
	const dst = new Uint8Array(8 + ctx.length);
	dst.set([18, 0, 0, 0, 0, 4, 0, usage]);
	dst.set(ctx, 8);
	const stream = xof(seed, dst, binder);
	try {
		return stream.xof(32);
	} finally {
		stream.destroy();
	}
}

/** Shard one bucket for the two-aggregator DAP profile. */
export function shardHistogramWithRandomness(
	measurement: number,
	length: number,
	chunkLength: number,
	ctx: Uint8Array,
	nonce: Uint8Array,
	rand: Uint8Array,
): { publicShare: Uint8Array; inputShares: [Uint8Array, Uint8Array] } {
	checkHistogram(length, chunkLength);
	validateHistogramMeasurement(measurement, length);
	requireBytes(ctx);
	requireBytes(nonce, 16);
	requireBytes(rand, 128);
	if (ctx.length > 65527) throw new RangeError("Context is too long");
	const meas = Array<bigint>(length).fill(0n);
	meas[measurement] = 1n;
	const calls = Math.ceil(length / chunkLength);
	let wireLength = 1;
	while (wireLength <= calls) wireLength *= 2;
	const arity = 2 * chunkLength;
	const proofLength = arity + 2 * wireLength - 1;
	const helper = rand.slice(0, 32);
	const helperBlind = rand.subarray(32, 64);
	const leaderBlind = rand.subarray(64, 96);
	const proveSeed = rand.subarray(96);
	const helperMeas = expand(
		helper,
		ctx,
		1,
		Uint8Array.of(1),
		length,
		4,
		P128,
		16,
	);
	const leaderMeas = meas.map((value, i) =>
		fieldMod(value - helperMeas[i]!, P128),
	);
	const leaderPart = deriveSeed(
		leaderBlind,
		ctx,
		7,
		new Uint8Array([0, ...nonce, ...encodeField(leaderMeas)]),
	);
	const helperPart = deriveSeed(
		helperBlind,
		ctx,
		7,
		new Uint8Array([1, ...nonce, ...encodeField(helperMeas)]),
	);
	const publicShare = new Uint8Array(64);
	publicShare.set(leaderPart);
	publicShare.set(helperPart, 32);
	const jointSeed = deriveSeed(new Uint8Array(32), ctx, 6, publicShare);
	const jointRands = expand(
		jointSeed,
		ctx,
		3,
		Uint8Array.of(1),
		calls,
		4,
		P128,
		16,
	);
	const seeds = expand(proveSeed, ctx, 4, Uint8Array.of(1), arity, 4, P128, 16);
	const wires = seeds.map((seed) => [
		seed,
		...Array<bigint>(wireLength - 1).fill(0n),
	]);
	for (let i = 0; i < calls; i++) {
		const r = jointRands[i]!;
		let rPower = r;
		for (let j = 0; j < chunkLength; j++) {
			const value = meas[i * chunkLength + j] ?? 0n;
			wires[2 * j]![i + 1] = fieldMod(rPower * value, P128);
			wires[2 * j + 1]![i + 1] = fieldMod(value - 1n, P128);
			rPower = fieldMod(rPower * r, P128);
		}
	}
	const gadget = Array<bigint>(2 * wireLength).fill(0n);
	for (let j = 0; j < arity; j += 2) {
		const left = transform(
			transform(wires[j]!, wireLength, P128, true),
			2 * wireLength,
			P128,
		);
		const right = transform(
			transform(wires[j + 1]!, wireLength, P128, true),
			2 * wireLength,
			P128,
		);
		for (let i = 0; i < gadget.length; i++)
			gadget[i] = fieldMod(gadget[i]! + left[i]! * right[i]!, P128);
	}
	const proof = [...seeds, ...gadget.slice(0, 2 * wireLength - 1)];
	const helperProof = expand(
		helper,
		ctx,
		2,
		Uint8Array.of(1, 1),
		proofLength,
		4,
		P128,
		16,
	);
	const leaderProof = proof.map((value, i) =>
		fieldMod(value - helperProof[i]!, P128),
	);
	const leader = new Uint8Array(16 * (length + proofLength) + 32);
	leader.set(encodeField(leaderMeas));
	leader.set(encodeField(leaderProof), 16 * length);
	leader.set(leaderBlind, leader.length - 32);
	const helperShare = new Uint8Array(64);
	helperShare.set(helper);
	helperShare.set(helperBlind, 32);
	return { publicShare, inputShares: [leader, helperShare] };
}

export function shardHistogram(
	measurement: number,
	length: number,
	chunkLength: number,
	ctx: Uint8Array,
	nonce: Uint8Array,
): { publicShare: Uint8Array; inputShares: [Uint8Array, Uint8Array] } {
	const rand = crypto.getRandomValues(new Uint8Array(128));
	try {
		return shardHistogramWithRandomness(
			measurement,
			length,
			chunkLength,
			ctx,
			nonce,
			rand,
		);
	} finally {
		rand.fill(0);
	}
}

export function unshardHistogram(
	shares: readonly [Uint8Array, Uint8Array],
	length: number,
): bigint[] {
	if (!Array.isArray(shares) || shares.length !== 2)
		throw new RangeError("Expected two aggregate shares");
	if (!Number.isSafeInteger(length) || length < 1 || length > 4096)
		throw new RangeError("Invalid histogram length");
	const result = Array<bigint>(length).fill(0n);
	for (const share of shares) {
		requireBytes(share, 16 * length);
		const view = new DataView(share.buffer, share.byteOffset, share.byteLength);
		for (let i = 0; i < length; i++) {
			const value =
				view.getBigUint64(i * 16, true) |
				(view.getBigUint64(i * 16 + 8, true) << 64n);
			if (value >= P128) throw new RangeError("Non-canonical Field128 element");
			result[i] = fieldMod(result[i]! + value, P128);
		}
	}
	return result;
}
