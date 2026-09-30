import { concat } from "./binary.js";
import { fieldMod, fieldPower, rootOfUnity, sizeInverse } from "./field.js";
import { expand, P, requireBytes, xof } from "./prio3-count.js";
import { P128 } from "./prio3-histogram.js";

function elements(
	input: Uint8Array,
	length: number,
	width: 8 | 16,
	modulus: bigint,
): bigint[] {
	requireBytes(input, length * width);
	const view = new DataView(input.buffer, input.byteOffset, input.byteLength);
	return Array.from({ length }, (_, i) => {
		const low = view.getBigUint64(i * width, true);
		const value =
			width === 8 ? low : low | (view.getBigUint64(i * width + 8, true) << 64n);
		if (value >= modulus) throw new RangeError("Non-canonical field element");
		return value;
	});
}

function encode(values: readonly bigint[], width: 8 | 16): Uint8Array {
	const output = new Uint8Array(values.length * width);
	const view = new DataView(output.buffer);
	for (let i = 0; i < values.length; i++) {
		view.setBigUint64(i * width, values[i]! & 0xffff_ffff_ffff_ffffn, true);
		if (width === 16) view.setBigUint64(i * width + 8, values[i]! >> 64n, true);
	}
	return output;
}

function lagrangeWeights(
	size: number,
	point: bigint,
	modulus: bigint,
): bigint[] {
	const root = rootOfUnity(size, modulus);
	const roots: bigint[] = [];
	const differences: bigint[] = [];
	const prefix = [1n];
	let power = 1n;
	for (let i = 0; i < size; i++) {
		roots.push(power);
		const difference = fieldMod(point - power, modulus);
		if (difference === 0n)
			return Array.from({ length: size }, (_, index) =>
				index === i ? 1n : 0n,
			);
		differences.push(difference);
		prefix.push(fieldMod(prefix[i]! * difference, modulus));
		power = fieldMod(power * root, modulus);
	}
	let inverse = fieldPower(prefix[size]!, modulus - 2n, modulus);
	const scale = fieldMod(
		(fieldPower(point, BigInt(size), modulus) - 1n) *
			sizeInverse(size, modulus),
		modulus,
	);
	const weights = Array<bigint>(size);
	for (let i = size - 1; i >= 0; i--) {
		weights[i] = fieldMod(scale * roots[i]! * inverse * prefix[i]!, modulus);
		inverse = fieldMod(inverse * differences[i]!, modulus);
	}
	return weights;
}

function polynomial(
	values: bigint[],
	weights: bigint[],
	modulus: bigint,
): bigint {
	let result = 0n;
	for (let i = 0; i < values.length; i++) result += values[i]! * weights[i]!;
	return fieldMod(result, modulus);
}

function gadget(values: bigint[], modulus: bigint): bigint[] {
	const size = values.length + 1;
	const root = rootOfUnity(size, modulus);
	let power = 1n;
	let weighted = 0n;
	for (const value of values) {
		weighted = fieldMod(weighted + value * power, modulus);
		power = fieldMod(power * root, modulus);
	}
	// The omitted final evaluation fixes the highest polynomial coefficient to zero.
	return [...values, fieldMod(-weighted * root, modulus)];
}

function seed(
	input: Uint8Array,
	context: Uint8Array,
	usage: number,
	binder: Uint8Array,
): Uint8Array {
	const dst = new Uint8Array(8 + context.length);
	dst.set([18, 0, 0, 0, 0, 4, 0, usage]);
	dst.set(context, 8);
	const stream = xof(input, dst, binder);
	try {
		return stream.xof(32);
	} finally {
		stream.destroy();
	}
}

export function sumVerifierShare(
	aggregatorId: 0 | 1,
	maxMeasurement: bigint,
	verifyKey: Uint8Array,
	context: Uint8Array,
	nonce: Uint8Array,
	publicShare: Uint8Array,
	inputShare: Uint8Array,
): { verifierShare: Uint8Array; outputShare: Uint8Array } {
	if (aggregatorId !== 0 && aggregatorId !== 1)
		throw new RangeError("Invalid aggregator ID");
	if (maxMeasurement <= 0n || maxMeasurement >= P)
		throw new RangeError("Invalid sum bound");
	requireBytes(verifyKey, 32);
	requireBytes(context);
	requireBytes(nonce, 16);
	requireBytes(publicShare, 0);
	const bits = maxMeasurement.toString(2).length;
	let p = 1;
	while (p <= bits) p *= 2;
	const proofLength = 2 * p;
	if (aggregatorId === 0) requireBytes(inputShare, (bits + proofLength) * 8);
	else requireBytes(inputShare, 32);
	const meas =
		aggregatorId === 0
			? elements(inputShare.subarray(0, bits * 8), bits, 8, P)
			: expand(inputShare, context, 1, Uint8Array.of(1), bits, 2);
	const proof =
		aggregatorId === 0
			? elements(inputShare.subarray(bits * 8), proofLength, 8, P)
			: expand(inputShare, context, 2, Uint8Array.of(1, 1), proofLength, 2);
	const query = expand(
		verifyKey,
		context,
		5,
		Uint8Array.of(1, ...nonce),
		bits + 1,
		2,
	);
	const point = query[bits]!;
	if (fieldPower(point, BigInt(p), P) === 1n)
		throw new RangeError("Invalid query point");
	let validity = 0n;
	for (let i = 0; i < bits; i++)
		validity = fieldMod(validity + query[i]! * proof[1 + 2 * (i + 1)]!, P);
	const wire = [proof[0]!, ...meas, ...Array<bigint>(p - bits - 1).fill(0n)];
	const wireCheck = polynomial(wire, lagrangeWeights(p, point, P), P);
	const gadgetCheck = polynomial(
		gadget(proof.slice(1), P),
		lagrangeWeights(2 * p, point, P),
		P,
	);
	const lastWeight = maxMeasurement - ((1n << BigInt(bits - 1)) - 1n);
	let output = lastWeight * meas[bits - 1]!;
	for (let i = 0; i < bits - 1; i++) output += (1n << BigInt(i)) * meas[i]!;
	return {
		verifierShare: encode([validity, wireCheck, gadgetCheck], 8),
		outputShare: encode([fieldMod(output, P)], 8),
	};
}

export function sumVerifierMessage(
	leaderShare: Uint8Array,
	helperShare: Uint8Array,
): Uint8Array {
	const a = elements(leaderShare, 3, 8, P);
	const b = elements(helperShare, 3, 8, P);
	const combined = a.map((value, i) => fieldMod(value + b[i]!, P));
	if (
		combined[0] !== 0n ||
		fieldMod(combined[1]! * combined[1]! - combined[1]!, P) !== combined[2]
	)
		throw new RangeError("Prio3Sum verification failed");
	return new Uint8Array();
}

export function histogramVerifierShare(
	aggregatorId: 0 | 1,
	length: number,
	chunkLength: number,
	verifyKey: Uint8Array,
	context: Uint8Array,
	nonce: Uint8Array,
	publicShare: Uint8Array,
	inputShare: Uint8Array,
): {
	verifierShare: Uint8Array;
	outputShare: Uint8Array;
	jointSeed: Uint8Array;
} {
	if (aggregatorId !== 0 && aggregatorId !== 1)
		throw new RangeError("Invalid aggregator ID");
	if (
		!Number.isSafeInteger(length) ||
		length < 1 ||
		length > 4096 ||
		!Number.isSafeInteger(chunkLength) ||
		chunkLength < 1 ||
		chunkLength > 4096
	)
		throw new RangeError("Invalid histogram parameters");
	requireBytes(verifyKey, 32);
	requireBytes(context);
	requireBytes(nonce, 16);
	requireBytes(publicShare, 64);
	const calls = Math.ceil(length / chunkLength);
	let p = 1;
	while (p <= calls) p *= 2;
	const arity = 2 * chunkLength;
	const proofLength = arity + 2 * p - 1;
	const inputLength =
		aggregatorId === 0 ? 16 * (length + proofLength) + 32 : 64;
	requireBytes(inputShare, inputLength);
	const meas =
		aggregatorId === 0
			? elements(inputShare.subarray(0, length * 16), length, 16, P128)
			: expand(
					inputShare.subarray(0, 32),
					context,
					1,
					Uint8Array.of(1),
					length,
					4,
					P128,
					16,
				);
	const proof =
		aggregatorId === 0
			? elements(
					inputShare.subarray(length * 16, inputLength - 32),
					proofLength,
					16,
					P128,
				)
			: expand(
					inputShare.subarray(0, 32),
					context,
					2,
					Uint8Array.of(1, 1),
					proofLength,
					4,
					P128,
					16,
				);
	const blind = inputShare.subarray(inputLength - 32);
	const part = seed(
		blind,
		context,
		7,
		concat(Uint8Array.of(aggregatorId), nonce, encode(meas, 16)),
	);
	const jointParts = publicShare.slice();
	jointParts.set(part, aggregatorId * 32);
	const jointSeed = seed(new Uint8Array(32), context, 6, jointParts);
	const joint = expand(
		jointSeed,
		context,
		3,
		Uint8Array.of(1),
		calls,
		4,
		P128,
		16,
	);
	const [reduceRange, reduceSum, point] = expand(
		verifyKey,
		context,
		5,
		Uint8Array.of(1, ...nonce),
		3,
		4,
		P128,
		16,
	) as [bigint, bigint, bigint];
	if (fieldPower(point, BigInt(p), P128) === 1n)
		throw new RangeError("Invalid query point");
	const inverseShares = fieldPower(2n, P128 - 2n, P128);
	const wires = proof
		.slice(0, arity)
		.map((value) => [value, ...Array<bigint>(p - 1).fill(0n)]);
	let rangeCheck = 0n;
	for (let i = 0; i < calls; i++) {
		let power = joint[i]!;
		for (let j = 0; j < chunkLength; j++) {
			const value = meas[i * chunkLength + j] ?? 0n;
			wires[2 * j]![i + 1] = fieldMod(power * value, P128);
			wires[2 * j + 1]![i + 1] = fieldMod(value - inverseShares, P128);
			power = fieldMod(power * joint[i]!, P128);
		}
		rangeCheck = fieldMod(rangeCheck + proof[arity + 2 * (i + 1)]!, P128);
	}
	const sumCheck = fieldMod(
		meas.reduce((sum, value) => sum + value, 0n) - inverseShares,
		P128,
	);
	const validity = fieldMod(
		reduceRange * rangeCheck + reduceSum * sumCheck,
		P128,
	);
	const wireWeights = lagrangeWeights(p, point, P128);
	const checks = wires.map((wire) => polynomial(wire, wireWeights, P128));
	const gadgetCheck = polynomial(
		gadget(proof.slice(arity), P128),
		lagrangeWeights(2 * p, point, P128),
		P128,
	);
	return {
		verifierShare: concat(encode([validity, ...checks, gadgetCheck], 16), part),
		outputShare: encode(meas, 16),
		jointSeed,
	};
}

export function histogramVerifierMessage(
	leaderShare: Uint8Array,
	helperShare: Uint8Array,
	chunkLength: number,
	context: Uint8Array,
): Uint8Array {
	const count = 2 * chunkLength + 2;
	requireBytes(leaderShare, count * 16 + 32);
	requireBytes(helperShare, count * 16 + 32);
	const a = elements(leaderShare.subarray(0, count * 16), count, 16, P128);
	const b = elements(helperShare.subarray(0, count * 16), count, 16, P128);
	const combined = a.map((value, i) => fieldMod(value + b[i]!, P128));
	if (combined[0] !== 0n)
		throw new RangeError("Prio3Histogram verification failed");
	let gadgetValue = 0n;
	for (let i = 1; i < count - 1; i += 2)
		gadgetValue = fieldMod(gadgetValue + combined[i]! * combined[i + 1]!, P128);
	if (gadgetValue !== combined[count - 1])
		throw new RangeError("Prio3Histogram verification failed");
	return seed(
		new Uint8Array(32),
		context,
		6,
		concat(leaderShare.subarray(count * 16), helperShare.subarray(count * 16)),
	);
}

export function addFieldOutputShare(
	current: Uint8Array,
	next: Uint8Array,
	width: 8 | 16,
): Uint8Array {
	if (current.length !== next.length || current.length % width)
		throw new RangeError("Output share lengths differ");
	const modulus = width === 8 ? P : P128;
	const a = elements(current, current.length / width, width, modulus);
	const b = elements(next, next.length / width, width, modulus);
	return encode(
		a.map((value, i) => fieldMod(value + b[i]!, modulus)),
		width,
	);
}
