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

export function concat(
	...parts: readonly Uint8Array[]
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

export function uint(value: number | bigint, width: 1 | 2 | 4 | 8): Uint8Array {
	if (typeof value !== "bigint" && !Number.isSafeInteger(value)) {
		throw new DAPError("InvalidMessage", "Expected an exact integer");
	}
	let remaining = BigInt(value);
	if (remaining < 0n || remaining >= 1n << BigInt(width * 8)) {
		throw new DAPError("InvalidMessage", "Integer is out of range");
	}
	const result = new Uint8Array(width);
	for (let i = width - 1; i >= 0; i--) {
		result[i] = Number(remaining & 255n);
		remaining >>= 8n;
	}
	return result;
}

export function vector(
	value: Uint8Array,
	width: 1 | 2 | 4,
	min = 0,
): Uint8Array {
	bytes(value);
	if (value.length < min) throw new DAPError("InvalidMessage", "Empty vector");
	return concat(uint(value.length, width), value);
}

// Internal cursor: length checks precede reads and allocations.
export class Reader {
	#offset = 0;
	constructor(private readonly input: Uint8Array) {
		bytes(input);
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
		const result = this.input.slice(this.#offset, this.#offset + length);
		this.#offset += length;
		return result;
	}
	uint(width: 1 | 2 | 4): number {
		return this.take(width).reduce((value, byte) => value * 256 + byte, 0);
	}
	u64(): bigint {
		return this.take(8).reduce(
			(value, byte) => (value << 8n) | BigInt(byte),
			0n,
		);
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

export function base64url(value: Uint8Array): string {
	let binary = "";
	for (const byte of value) binary += String.fromCharCode(byte);
	return btoa(binary)
		.replaceAll("+", "-")
		.replaceAll("/", "_")
		.replace(/=+$/, "");
}

export function decodeId(value: string, length: number): Uint8Array {
	if (
		typeof value !== "string" ||
		!/^[A-Za-z0-9_-]+$/.test(value) ||
		value.length !== Math.ceil((length * 8) / 6)
	) {
		throw new DAPError("InvalidMessage", "Invalid identifier");
	}
	const decoded = Uint8Array.from(
		atob(value.replaceAll("-", "+").replaceAll("_", "/")),
		(c) => c.charCodeAt(0),
	);
	if (decoded.length !== length || base64url(decoded) !== value) {
		throw new DAPError("InvalidMessage", "Non-canonical identifier");
	}
	return decoded;
}
