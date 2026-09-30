export type DAPErrorCode =
	| "InvalidMessage"
	| "InvalidTask"
	| "InvalidMeasurement"
	| "UnsupportedVdaf"
	| "UnsupportedCipherSuite"
	| "InvalidHpkeConfig"
	| "EncryptionFailed"
	| "DecryptionFailed"
	| "InvalidReport"
	| "InvalidResponse"
	| "HttpError";

/** Problem types registered in DAP 19, Section 3.6. */
export type DAPProblemType =
	| "invalidMessage"
	| "unrecognizedTask"
	| "unrecognizedAggregationJob"
	| "batchInvalid"
	| "invalidBatchSize"
	| "invalidAggregationParameter"
	| "batchMismatch"
	| "stepMismatch"
	| "batchOverlap"
	| "unsupportedExtension"
	| "invalidExtension";

/** RFC 9457 problem details returned with a DAP error response (DAP 19, 3.6). */
export interface DAPProblem {
	readonly type: string;
	/**
	 * Registered token when `type` is a DAP error URN, such as
	 * `invalidBatchSize` or `unrecognizedTask`. Absent for other URIs.
	 */
	readonly dapError?: string;
	readonly title?: string;
	readonly detail?: string;
	readonly taskId?: string;
}

export interface DAPErrorOptions extends ErrorOptions {
	readonly problem?: DAPProblem;
	readonly type?: DAPProblemType;
}

export class DAPError extends Error {
	override readonly name = "DAPError";
	readonly code: DAPErrorCode;
	/** Present when the peer returned a problem detail document. */
	readonly problem: DAPProblem | undefined;
	/** The problem type a server should answer with, when the spec names one. */
	readonly type: DAPProblemType | undefined;
	constructor(code: DAPErrorCode, message: string, options?: DAPErrorOptions) {
		super(message, options);
		this.code = code;
		this.problem = options?.problem;
		this.type =
			options?.type ??
			(code === "InvalidMessage" ? "invalidMessage" : undefined);
	}
}

export function isDAPError(error: unknown): error is DAPError {
	return error instanceof DAPError;
}

/**
 * Build the RFC 9457 response for an error raised while serving a DAP
 * request. Errors this library did not raise become an opaque 500, so
 * internal details never reach the peer.
 */
export function problemResponse(error: unknown, taskId?: string): Response {
	const known = error instanceof DAPError;
	const type = known ? (error.type ?? "invalidMessage") : undefined;
	const status = !type
		? 500
		: type === "unrecognizedTask" || type === "unrecognizedAggregationJob"
			? 404
			: 400;
	return new Response(
		JSON.stringify({
			type: type ? `urn:ietf:params:ppm:dap:error:${type}` : "about:blank",
			title: known ? error.message : "Internal server error",
			status,
			...(taskId ? { taskid: taskId } : {}),
		}),
		{
			status,
			headers: {
				"content-type": "application/problem+json",
				"cache-control": "no-store",
			},
		},
	);
}
