import { DAPError } from "./errors.js";

export function bytes(value: Uint8Array, length?: number): Uint8Array {
	if (
		!(value instanceof Uint8Array) ||
		(length !== undefined && value.length !== length)
	) {
		throw new DAPError(
			"InvalidMessage",
			`Expected ${length ?? "a sequence of"} bytes`,
		);
	}
	return value;
}

/**
 * An owned copy. Buffer.prototype.slice returns a view, so never use slice()
 * to take ownership of caller bytes.
 */
export function copy(value: Uint8Array): Uint8Array<ArrayBuffer> {
	return new Uint8Array(bytes(value));
}

export function concat(
	...parts: readonly Uint8Array[]
): Uint8Array<ArrayBuffer> {
	return concatParts(parts);
}

export function concatParts(
	parts: readonly Uint8Array[],
): Uint8Array<ArrayBuffer> {
	const result = new Uint8Array(
		parts.reduce((sum, part) => sum + bytes(part).length, 0),
	);
	let offset = 0;
	for (const part of parts) {
		result.set(part, offset);
		offset += part.length;
	}
	return result;
}

export function uint(
	value: number | bigint,
	width: 1 | 2 | 4 | 8,
): Uint8Array<ArrayBuffer> {
	const result = new Uint8Array(width);
	const view = new DataView(result.buffer);
	if (typeof value === "number") {
		if (!Number.isSafeInteger(value))
			throw new DAPError("InvalidMessage", "Expected an exact integer");
		if (value < 0 || (width < 8 && value >= 2 ** (width * 8)))
			throw new DAPError("InvalidMessage", "Integer is out of range");
		if (width === 8) view.setBigUint64(0, BigInt(value));
		else if (width === 4) view.setUint32(0, value);
		else if (width === 2) view.setUint16(0, value);
		else result[0] = value;
		return result;
	}
	if (typeof value !== "bigint" || value < 0n || value > 0xffff_ffff_ffff_ffffn)
		throw new DAPError("InvalidMessage", "Integer is out of range");
	if (width < 8) return uint(Number(value), width);
	view.setBigUint64(0, value);
	return result;
}

export function vector(
	value: Uint8Array,
	width: 1 | 2 | 4,
	min = 0,
): Uint8Array<ArrayBuffer> {
	bytes(value);
	if (value.length < min) throw new DAPError("InvalidMessage", "Empty vector");
	return concat(uint(value.length, width), value);
}

// Internal cursor: length checks precede reads and allocations.
export class Reader {
	#offset = 0;
	#view: DataView;
	constructor(private readonly input: Uint8Array) {
		bytes(input);
		this.#view = new DataView(input.buffer, input.byteOffset, input.byteLength);
	}
	get remaining(): number {
		return this.input.length - this.#offset;
	}
	take(length: number): Uint8Array {
		if (
			!Number.isSafeInteger(length) ||
			length < 0 ||
			length > this.remaining
		) {
			throw new DAPError("InvalidMessage", "Truncated message");
		}
		const result = copy(
			this.input.subarray(this.#offset, this.#offset + length),
		);
		this.#offset += length;
		return result;
	}
	uint(width: 1 | 2 | 4): number {
		if (this.remaining < width)
			throw new DAPError("InvalidMessage", "Truncated message");
		const offset = this.#offset;
		this.#offset += width;
		return width === 4
			? this.#view.getUint32(offset)
			: width === 2
				? this.#view.getUint16(offset)
				: this.#view.getUint8(offset);
	}
	u64(): bigint {
		if (this.remaining < 8)
			throw new DAPError("InvalidMessage", "Truncated message");
		const value = this.#view.getBigUint64(this.#offset);
		this.#offset += 8;
		return value;
	}
	vector(width: 1 | 2 | 4, min = 0): Uint8Array {
		const length = this.uint(width);
		if (length < min)
			throw new DAPError("InvalidMessage", "Vector is too short");
		return this.take(length);
	}
	end(): void {
		if (this.remaining) throw new DAPError("InvalidMessage", "Trailing bytes");
	}
}

const ALPHABET =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const LOOKUP = new Int8Array(128).fill(-1);
for (let i = 0; i < 64; i++) LOOKUP[ALPHABET.charCodeAt(i)] = i;

/** URL-safe, unpadded Base 64 (RFC 4648, Section 5). */
export function base64url(value: Uint8Array): string {
	let result = "";
	let i = 0;
	for (; i + 2 < value.length; i += 3) {
		const n = (value[i]! << 16) | (value[i + 1]! << 8) | value[i + 2]!;
		result +=
			ALPHABET[n >> 18]! +
			ALPHABET[(n >> 12) & 63]! +
			ALPHABET[(n >> 6) & 63]! +
			ALPHABET[n & 63]!;
	}
	if (i < value.length) {
		const n = (value[i]! << 16) | ((value[i + 1] ?? 0) << 8);
		result += ALPHABET[n >> 18]! + ALPHABET[(n >> 12) & 63]!;
		if (i + 1 < value.length) result += ALPHABET[(n >> 6) & 63]!;
	}
	return result;
}

/** Decode a fixed-length ID, rejecting any non-canonical encoding. */
export function decodeId(value: string, length: number): Uint8Array {
	if (typeof value !== "string" || value.length !== Math.ceil((length * 8) / 6))
		throw new DAPError("InvalidMessage", "Invalid identifier");
	const result = new Uint8Array(length);
	let buffer = 0;
	let bits = 0;
	let offset = 0;
	for (let i = 0; i < value.length; i++) {
		const code = value.charCodeAt(i);
		const digit = code < 128 ? LOOKUP[code]! : -1;
		if (digit < 0) throw new DAPError("InvalidMessage", "Invalid identifier");
		buffer = ((buffer << 6) | digit) & 0xfff;
		bits += 6;
		if (bits >= 8) {
			bits -= 8;
			result[offset++] = (buffer >> bits) & 255;
		}
	}
	// Leftover bits must be zero, so each ID has exactly one encoding.
	if (buffer & ((1 << bits) - 1))
		throw new DAPError("InvalidMessage", "Non-canonical identifier");
	return result;
}
