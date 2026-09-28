export type {
	ClientOptions,
	DAPRequest,
	DAPResponse,
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
export type Collector = import("./collector.js").Collector;
export type { DAPErrorCode } from "./errors.js";
export { DAPError, isDAPError } from "./errors.js";
export type { AggregatorHpkeConfigs, RandomSource } from "./hpke.js";
export { HpkeConfigList } from "./hpke.js";
export { prio3Count } from "./prio3-count.js";
export { prio3Histogram } from "./prio3-histogram.js";
export { prio3Sum } from "./prio3-sum.js";
export type { PreparedReport, ReportId } from "./reports.js";
export type { EncodedTask, TaskOptions } from "./task.js";
export { Task } from "./task.js";

import type { HpkeConfig, Report } from "./messages.js";
import type { Task } from "./task.js";

export type AggregatorOptions = {
	readonly hpke: { readonly configId: number; readonly privateKey: Uint8Array };
	readonly verificationKeyId: number;
	readonly verifyKey: Uint8Array;
};

export const Leader = {
	async create(task: Task<unknown>, options: AggregatorOptions) {
		const core = await import("./aggregator.js");
		const key = await core.prepareAggregatorKey(options.hpke);
		return {
			prepare: (reports: readonly Report[], nowMs?: number) =>
				core.leaderPrio3BatchInit(
					task,
					reports,
					key,
					options.verificationKeyId,
					options.verifyKey,
					nowMs,
				),
			finish: (
				reports: Parameters<typeof core.leaderPrio3BatchFinish>[1],
				response: Uint8Array,
			) => core.leaderPrio3BatchFinish(task, reports, response),
			addShare: (current: Uint8Array, next: Uint8Array) =>
				core.addPrio3OutputShare(task, current, next),
			encryptShare: (
				request: Uint8Array,
				share: Uint8Array,
				collector: HpkeConfig,
			) =>
				core.encryptAggregateShare(task, "leader", request, share, collector),
		};
	},
} as const;

export const Helper = {
	async create(task: Task<unknown>, options: AggregatorOptions) {
		const core = await import("./aggregator.js");
		const key = await core.prepareAggregatorKey(options.hpke);
		return {
			verify: (request: Uint8Array, nowMs?: number) =>
				core.helperPrio3BatchInit(
					task,
					request,
					key,
					options.verificationKeyId,
					options.verifyKey,
					nowMs,
				),
			reject: core.encodeCountJobRejection,
			addShare: (current: Uint8Array, next: Uint8Array) =>
				core.addPrio3OutputShare(task, current, next),
			encryptShare: (
				request: Uint8Array,
				share: Uint8Array,
				collector: HpkeConfig,
			) =>
				core.encryptAggregateShare(task, "helper", request, share, collector),
		};
	},
} as const;

export const Collector = {
	async create(
		task: Task<number | bigint>,
		options: import("./collector.js").CollectorOptions,
	) {
		const { Collector } = await import("./collector.js");
		return new Collector(task, options);
	},
} as const;
