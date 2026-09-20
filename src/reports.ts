import { DAPError } from "./errors.js";

declare const reportIdBrand: unique symbol;
export type ReportId = string & { readonly [reportIdBrand]: true };
declare const reportBrand: unique symbol;
export interface PreparedReport {
	readonly id: ReportId;
	/** DAP time-precision units since the Unix epoch. */
	readonly time: number;
	readonly [reportBrand]: true;
}

const reports = new WeakMap<
	PreparedReport,
	{ task: string; bytes: Uint8Array }
>();

export function preparedReport(
	id: ReportId,
	time: number,
	task: string,
	bytes: Uint8Array,
): PreparedReport {
	const report = Object.freeze({ id, time }) as PreparedReport;
	reports.set(report, { task, bytes: bytes.slice() });
	return report;
}

export function reportBytes(report: PreparedReport, task?: string): Uint8Array {
	const stored = reports.get(report);
	if (!stored || (task !== undefined && stored.task !== task)) {
		throw new DAPError("InvalidReport", "Report does not belong to this task");
	}
	return stored.bytes.slice();
}

export function isPreparedReport(value: object): value is PreparedReport {
	return reports.has(value as PreparedReport);
}
