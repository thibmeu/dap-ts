export function fieldMod(value: bigint, modulus: bigint): bigint {
	return ((value % modulus) + modulus) % modulus;
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
		const root = fieldPower(7n, (modulus - 1n) / BigInt(width), modulus);
		const step = inverse ? fieldPower(root, modulus - 2n, modulus) : root;
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
		const scale = fieldPower(BigInt(size), modulus - 2n, modulus);
		for (let i = 0; i < size; i++) out[i] = fieldMod(out[i]! * scale, modulus);
	}
	return out;
}
