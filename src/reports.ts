import { DAPError } from "./errors.js";

declare const reportIdBrand: unique symbol;
/** A report ID in URL-safe, unpadded Base 64, as DAP writes IDs in URLs. */
export type ReportId = string & { readonly [reportIdBrand]: true };

/** Report errors registered in DAP 19, Section 4.1. */
export type ReportError =
	| "batch-collected"
	| "report-replayed"
	| "report-dropped"
	| "hpke-unknown-config-id"
	| "hpke-decrypt-error"
	| "vdaf-verify-error"
	| "invalid-message"
	| "report-too-early"
	| "unknown-verification-key-id"
	| "unsupported-extension";

/** Codepoint order; index 0 is reserved. */
export const reportErrors: readonly (ReportError | undefined)[] = [
	undefined,
	"batch-collected",
	"report-replayed",
	"report-dropped",
	"hpke-unknown-config-id",
	"hpke-decrypt-error",
	"vdaf-verify-error",
	"invalid-message",
	"report-too-early",
	"unknown-verification-key-id",
	"unsupported-extension",
];

export function reportErrorCode(error: ReportError): number {
	const code = reportErrors.indexOf(error);
	if (code < 1) throw new DAPError("InvalidMessage", "Unknown report error");
	return code;
}
declare const reportBrand: unique symbol;
export interface PreparedReport {
	readonly id: ReportId;
	/** Unix milliseconds, truncated to the task's time precision. */
	readonly time: number;
	readonly [reportBrand]: true;
}

const reports = new WeakMap<
	PreparedReport,
	{ task: string; bytes: Uint8Array<ArrayBuffer> }
>();

export function preparedReport(
	id: ReportId,
	time: number,
	task: string,
	bytes: Uint8Array<ArrayBuffer>,
): PreparedReport {
	const report = Object.freeze({ id, time }) as PreparedReport;
	// Adopts bytes: callers pass a fresh encoding they never retain.
	reports.set(report, { task, bytes });
	return report;
}

/** @internal The stored encoding, borrowed. Copy before exposing it. */
export function reportBytes(
	report: PreparedReport,
	task?: string,
): Uint8Array<ArrayBuffer> {
	const stored = reports.get(report);
	if (!stored || (task !== undefined && stored.task !== task)) {
		throw new DAPError("InvalidReport", "Report does not belong to this task");
	}
	return stored.bytes;
}

export function isPreparedReport(value: object): value is PreparedReport {
	return reports.has(value as PreparedReport);
}
