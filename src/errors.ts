export type DAPErrorCode =
	| "InvalidMessage"
	| "InvalidTask"
	| "InvalidMeasurement"
	| "UnsupportedVdaf"
	| "UnsupportedCipherSuite"
	| "InvalidHpkeConfig"
	| "EncryptionFailed"
	| "InvalidReport"
	| "InvalidResponse"
	| "HttpError";

export class DAPError extends Error {
	override readonly name = "DAPError";
	constructor(
		readonly code: DAPErrorCode,
		message: string,
		options?: ErrorOptions,
	) {
		super(message, options);
	}
}

export function isDAPError(error: unknown): error is DAPError {
	return error instanceof DAPError;
}
