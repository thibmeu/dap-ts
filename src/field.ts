export function fieldMod(value: bigint, modulus: bigint): bigint {
	// One BigInt division, not two: products are almost always non-negative.
	const remainder = value % modulus;
	return remainder < 0n ? remainder + modulus : remainder;
}

export function fieldPower(
	base: bigint,
	exponent: bigint,
	modulus: bigint,
): bigint {
	let result = 1n;
	while (exponent) {
		if (exponent & 1n) result = fieldMod(result * base, modulus);
		base = fieldMod(base * base, modulus);
		exponent >>= 1n;
	}
	return result;
}

// Roots of unity and size inverses depend only on (size, modulus), and both
// are powers of two bounded by the histogram length cap, so this cache holds
// a few dozen entries at most.
const constants = new Map<string, bigint>();
function cached(
	kind: string,
	size: number,
	modulus: bigint,
	compute: () => bigint,
): bigint {
	const key = `${kind}:${size}:${modulus}`;
	let value = constants.get(key);
	if (value === undefined) {
		value = compute();
		constants.set(key, value);
	}
	return value;
}

/** The principal size-th root of unity for a Field64 or Field128 modulus. */
export function rootOfUnity(size: number, modulus: bigint): bigint {
	return cached("root", size, modulus, () =>
		fieldPower(7n, (modulus - 1n) / BigInt(size), modulus),
	);
}

export function sizeInverse(size: number, modulus: bigint): bigint {
	return cached("inv", size, modulus, () =>
		fieldPower(BigInt(size), modulus - 2n, modulus),
	);
}

// Evaluate at successive roots of unity; inverse transforms evaluations to coefficients.
export function transform(
	values: bigint[],
	size: number,
	modulus: bigint,
	inverse = false,
): bigint[] {
	const out = Array<bigint>(size).fill(0n);
	for (let i = 0; i < values.length; i++) out[i] = values[i]!;
	for (let i = 1, j = 0; i < size; i++) {
		let bit = size >> 1;
		for (; j & bit; bit >>= 1) j ^= bit;
		j ^= bit;
		if (i < j) [out[i], out[j]] = [out[j]!, out[i]!];
	}
	for (let width = 2; width <= size; width *= 2) {
		const root = rootOfUnity(width, modulus);
		// root has order width, so its inverse is root^(width-1): a far shorter
		// exponent than the generic root^(modulus-2).
		const step = inverse
			? cached("iroot", width, modulus, () =>
					fieldPower(root, BigInt(width - 1), modulus),
				)
			: root;
		for (let start = 0; start < size; start += width) {
			let factor = 1n;
			for (let j = 0; j < width / 2; j++) {
				const a = out[start + j]!;
				const b = fieldMod(out[start + j + width / 2]! * factor, modulus);
				out[start + j] = fieldMod(a + b, modulus);
				out[start + j + width / 2] = fieldMod(a - b, modulus);
				factor = fieldMod(factor * step, modulus);
			}
		}
	}
	if (inverse) {
		const scale = sizeInverse(size, modulus);
		for (let i = 0; i < size; i++) out[i] = fieldMod(out[i]! * scale, modulus);
	}
	return out;
}
