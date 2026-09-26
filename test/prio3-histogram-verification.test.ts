import { expect, it } from "vitest";
import { fieldMod, fieldPower, transform } from "../src/field.js";
import { expand, xof } from "../src/prio3-count.js";
import { P128 } from "../src/prio3-histogram.js";
import histogram0 from "./vectors/Prio3Histogram_0.json";
import histogram2 from "./vectors/Prio3Histogram_2.json";
import badHelperBlind from "./vectors/Prio3Histogram_bad_helper_jr_blind.json";
import badLeaderBlind from "./vectors/Prio3Histogram_bad_leader_jr_blind.json";
import badPublicShare from "./vectors/Prio3Histogram_bad_public_share.json";
import badVerifierMessage from "./vectors/Prio3Histogram_bad_verifier_message.json";

const bytes = (hex: string) => Uint8Array.fromHex(hex);
const mod = (value: bigint) => fieldMod(value, P128);

function elements(input: Uint8Array): bigint[] {
	if (input.length % 16) throw new RangeError("Invalid field vector length");
	const view = new DataView(input.buffer, input.byteOffset, input.byteLength);
	return Array.from({ length: input.length / 16 }, (_, i) => {
		const value =
			view.getBigUint64(16 * i, true) |
			(view.getBigUint64(16 * i + 8, true) << 64n);
		if (value >= P128) throw new RangeError("Non-canonical field element");
		return value;
	});
}

function encoded(values: bigint[]): Uint8Array {
	const output = new Uint8Array(values.length * 16);
	const view = new DataView(output.buffer);
	for (const [i, value] of values.entries()) {
		view.setBigUint64(i * 16, value & 0xffff_ffff_ffff_ffffn, true);
		view.setBigUint64(i * 16 + 8, value >> 64n, true);
	}
	return output;
}

function seed(
	input: Uint8Array,
	ctx: Uint8Array,
	usage: number,
	binder: Uint8Array,
): Uint8Array {
	const dst = Uint8Array.of(18, 0, 0, 0, 0, 4, 0, usage, ...ctx);
	const stream = xof(input, dst, binder);
	try {
		return stream.xof(32);
	} finally {
		stream.destroy();
	}
}

// The proof uses evaluations at roots of unity. Interpolate, then evaluate at t.
function evaluate(values: bigint[], t: bigint): bigint {
	const coefficients = transform(values, values.length, P128, true);
	return coefficients.reduceRight(
		(acc, coefficient) => mod(acc * t + coefficient),
		0n,
	);
}

function verifierShares(
	length: number,
	chunkLength: number,
	ctx: Uint8Array,
	nonce: Uint8Array,
	verifyKey: Uint8Array,
	publicShare: Uint8Array,
	inputShares: [Uint8Array, Uint8Array],
): [Uint8Array, Uint8Array] {
	const calls = Math.ceil(length / chunkLength);
	let p = 1;
	while (p <= calls) p *= 2;
	const arity = 2 * chunkLength;
	const proofLength = arity + 2 * p - 1;
	const query = expand(
		verifyKey,
		ctx,
		5,
		Uint8Array.of(1, ...nonce),
		3,
		4,
		P128,
		16,
	);
	const [reduceRange, reduceSum, t] = query as [bigint, bigint, bigint];
	if (fieldPower(t, BigInt(p), P128) === 1n)
		throw new RangeError("Invalid query point");
	const publicParts = [publicShare.subarray(0, 32), publicShare.subarray(32)];
	const inverseShares = fieldPower(2n, P128 - 2n, P128);
	const results: Uint8Array[] = [];
	for (const aggId of [0, 1]) {
		const input = inputShares[aggId]!;
		let meas: bigint[];
		let proof: bigint[];
		let blind: Uint8Array;
		if (aggId === 0) {
			meas = elements(input.subarray(0, length * 16));
			proof = elements(
				input.subarray(length * 16, (length + proofLength) * 16),
			);
			blind = input.subarray(input.length - 32);
		} else {
			const helperSeed = input.subarray(0, 32);
			meas = expand(helperSeed, ctx, 1, Uint8Array.of(1), length, 4, P128, 16);
			proof = expand(
				helperSeed,
				ctx,
				2,
				Uint8Array.of(1, 1),
				proofLength,
				4,
				P128,
				16,
			);
			blind = input.subarray(32);
		}
		const part = seed(
			blind,
			ctx,
			7,
			Uint8Array.of(aggId, ...nonce, ...encoded(meas)),
		);
		const parts = publicParts.map((value, i) => (i === aggId ? part : value));
		const jointSeed = seed(
			new Uint8Array(32),
			ctx,
			6,
			Uint8Array.of(...parts[0]!, ...parts[1]!),
		);
		const joint = expand(
			jointSeed,
			ctx,
			3,
			Uint8Array.of(1),
			calls,
			4,
			P128,
			16,
		);
		const wires = proof
			.slice(0, arity)
			.map((wireSeed) => [wireSeed, ...Array<bigint>(p - 1).fill(0n)]);
		let rangeCheck = 0n;
		for (let i = 0; i < calls; i++) {
			let power = joint[i]!;
			for (let j = 0; j < chunkLength; j++) {
				const value = meas[i * chunkLength + j] ?? 0n;
				wires[2 * j]![i + 1] = mod(power * value);
				wires[2 * j + 1]![i + 1] = mod(value - inverseShares);
				power = mod(power * joint[i]!);
			}
			rangeCheck = mod(rangeCheck + proof[arity + 2 * (i + 1)]!);
		}
		const sumCheck = mod(
			meas.reduce((sum, value) => sum + value, 0n) - inverseShares,
		);
		const v = mod(reduceRange * rangeCheck + reduceSum * sumCheck);
		const wireChecks = wires.map((wire) => evaluate(wire, t));
		const gadget = proof.slice(arity);
		const n = 2 * p;
		const root = fieldPower(7n, (P128 - 1n) / BigInt(n), P128);
		let rootPower = 1n;
		let weighted = 0n;
		for (const value of gadget) {
			weighted = mod(weighted + value * rootPower);
			rootPower = mod(rootPower * root);
		}
		gadget.push(mod(-weighted * fieldPower(rootPower, P128 - 2n, P128)));
		const gadgetCheck = evaluate(gadget, t);
		results.push(
			Uint8Array.of(...encoded([v, ...wireChecks, gadgetCheck]), ...part),
		);
	}
	return results as [Uint8Array, Uint8Array];
}

function accept(
	shares: [Uint8Array, Uint8Array],
	ctx: Uint8Array,
	message?: Uint8Array,
): boolean {
	const fields = shares.map((share) =>
		elements(share.subarray(0, share.length - 32)),
	);
	const verifier = fields[0]!.map((value, i) => mod(value + fields[1]![i]!));
	if (verifier[0] !== 0n) return false;
	let gadget = 0n;
	for (let i = 1; i < verifier.length - 1; i += 2)
		gadget = mod(gadget + verifier[i]! * verifier[i + 1]!);
	if (gadget !== verifier.at(-1)) return false;
	const parts = shares.map((share) => share.subarray(share.length - 32));
	const expected = seed(
		new Uint8Array(32),
		ctx,
		6,
		Uint8Array.of(...parts[0]!, ...parts[1]!),
	);
	return (
		message === undefined ||
		(expected.every((byte, i) => byte === message[i]) && message.length === 32)
	);
}

for (const [name, vector] of Object.entries({ histogram0, histogram2 })) {
	it(`${name}: matches published verifier shares and accepts valid reports`, () => {
		for (const report of vector.reports) {
			const ctx = bytes(vector.ctx);
			const shares = verifierShares(
				vector.length,
				vector.chunk_length,
				ctx,
				bytes(report.nonce),
				bytes(vector.verify_key),
				bytes(report.public_share),
				report.input_shares.map(bytes) as [Uint8Array, Uint8Array],
			);
			expect(shares).toEqual(report.verifier_shares[0]!.map(bytes));
			expect(accept(shares, ctx, bytes(report.verifier_messages[0]!))).toBe(
				true,
			);
		}
	});
}

for (const [name, vector] of Object.entries({
	badHelperBlind,
	badLeaderBlind,
	badPublicShare,
	badVerifierMessage,
})) {
	it(`${name}: rejects the published malformed transcript`, () => {
		const report = vector.reports[0]!;
		const ctx = bytes(vector.ctx);
		const shares = verifierShares(
			vector.length,
			vector.chunk_length,
			ctx,
			bytes(report.nonce),
			bytes(vector.verify_key),
			bytes(report.public_share),
			report.input_shares.map(bytes) as [Uint8Array, Uint8Array],
		);
		expect(shares.slice(0, report.verifier_shares[0]!.length)).toEqual(
			report.verifier_shares[0]!.map(bytes),
		);
		expect(
			accept(
				shares,
				ctx,
				report.verifier_messages[0]
					? bytes(report.verifier_messages[0])
					: undefined,
			),
		).toBe(false);
	});
}

it("rejects changed proof, measurement, and joint randomness", () => {
	const vector = histogram0;
	const report = vector.reports[0]!;
	const ctx = bytes(vector.ctx);
	const nonce = bytes(report.nonce);
	const verifyKey = bytes(vector.verify_key);
	const publicShare = bytes(report.public_share);
	const inputShares = report.input_shares.map(bytes) as [
		Uint8Array,
		Uint8Array,
	];
	const check = (pub: Uint8Array, inputs: [Uint8Array, Uint8Array]) =>
		accept(
			verifierShares(
				vector.length,
				vector.chunk_length,
				ctx,
				nonce,
				verifyKey,
				pub,
				inputs,
			),
			ctx,
		);
	const proof = [inputShares[0].slice(), inputShares[1].slice()] as [
		Uint8Array,
		Uint8Array,
	];
	proof[0][vector.length * 16] ^= 1;
	expect(check(publicShare, proof)).toBe(false);
	const measurement = [inputShares[0].slice(), inputShares[1].slice()] as [
		Uint8Array,
		Uint8Array,
	];
	measurement[0][0] ^= 1;
	expect(check(publicShare, measurement)).toBe(false);
	const pub = publicShare.slice();
	pub[0] ^= 1;
	expect(check(pub, inputShares)).toBe(false);
	const blind = [inputShares[0].slice(), inputShares[1].slice()] as [
		Uint8Array,
		Uint8Array,
	];
	blind[1][32] ^= 1;
	expect(check(publicShare, blind)).toBe(false);
});
