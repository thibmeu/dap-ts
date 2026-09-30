export type {
	AggregatedReport,
	AggregateShareJob,
	AggregationJob,
	AggregatorHpkeKey,
	AggregatorOptions,
	CollectionJob,
	Interval,
	ReportRef,
	ReportRejectionEntry,
	Upload,
	UploadedReport,
	VerifiedJob,
	VerifyKey,
} from "./aggregator.js";
export type {
	ClientOptions,
	PreparedUpload,
	PrepareReportOptions,
	ReportRejection,
	UploadResult,
} from "./client.js";
export { Client, checkMediaType } from "./client.js";
export type {
	CollectionProgress,
	CollectionQuery,
	CollectionState,
	CollectorOptions,
	PreparedCollection,
} from "./collector.js";
export { Collector } from "./collector.js";
export type { DAPErrorCode, DAPProblem, DAPProblemType } from "./errors.js";
export { DAPError, isDAPError, problemResponse } from "./errors.js";
export type { AggregatorHpkeConfigs, RandomSource } from "./hpke.js";
export { HpkeConfigList } from "./hpke.js";
export type { HpkeCiphertext, HpkeConfig, Report } from "./messages.js";
export type { PreparedReport, ReportError, ReportId } from "./reports.js";
export type { EncodedTask, TaskOptions } from "./task.js";
export { Task } from "./task.js";
export type {
	AggregateResult,
	Measurement,
	Prio3Count,
	Prio3Histogram,
	Prio3Sum,
	Vdaf,
} from "./vdaf.js";
export { prio3Count, prio3Histogram, prio3Sum } from "./vdaf.js";

import type {
	AggregatorOptions,
	Helper as HelperRole,
	Leader as LeaderRole,
} from "./aggregator.js";
import type { Task } from "./task.js";
import type { Vdaf } from "./vdaf.js";

// The aggregator roles load their module lazily so that a reporting-only
// bundle does not pull in verification.
export type Leader<V extends Vdaf = Vdaf> = LeaderRole<V>;
export type Helper<V extends Vdaf = Vdaf> = HelperRole<V>;
export const Leader = {
	async create<V extends Vdaf>(
		task: Task<V>,
		options: AggregatorOptions,
	): Promise<Leader<V>> {
		return (await import("./aggregator.js")).Leader.create(task, options);
	},
};
export const Helper = {
	async create<V extends Vdaf>(
		task: Task<V>,
		options: AggregatorOptions,
	): Promise<Helper<V>> {
		return (await import("./aggregator.js")).Helper.create(task, options);
	},
};
