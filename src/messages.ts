import { base64url, bytes, concat, Reader, uint, vector } from "./binary.js";
import { DAPError } from "./errors.js";
import {
	isPreparedReport,
	type PreparedReport,
	reportBytes,
} from "./reports.js";

export interface Extension {
	readonly type: number;
	readonly data: Uint8Array;
}
export interface HpkeConfig {
	readonly id: number;
	readonly kemId: number;
	readonly kdfId: number;
	readonly aeadId: number;
	readonly publicKey: Uint8Array;
}
export interface TaskConfiguration {
	readonly info: Uint8Array;
	readonly leader: Uint8Array;
	readonly helper: Uint8Array;
	readonly timePrecision: bigint;
	readonly minBatchSize: bigint;
	readonly batchMode: number;
	readonly batchConfig: Uint8Array;
	readonly vdafType: number;
	readonly vdafConfig: Uint8Array;
	readonly extensions: readonly Extension[];
}
export interface DecodeOptions {
	readonly maxTaskInfoSize?: number;
	readonly maxExtensions?: number;
}
export interface ReportMetadata {
	readonly id: Uint8Array;
	readonly time: bigint;
	readonly publicExtensions: readonly Extension[];
}
export interface HpkeCiphertext {
	readonly configId: number;
	readonly enc: Uint8Array;
	readonly payload: Uint8Array;
}
export interface Report {
	readonly metadata: ReportMetadata;
	readonly publicShare: Uint8Array;
	readonly leader: HpkeCiphertext;
	readonly helper: HpkeCiphertext;
}

export function encodeExtensions(
	extensions: readonly Extension[],
	sorted = false,
): Uint8Array {
	const seen = new Set<number>();
	let previous = -1;
	const parts = extensions.map((extension) => {
		if (seen.has(extension.type) || (sorted && extension.type <= previous)) {
			throw new DAPError("InvalidMessage", "Duplicate or unordered extension");
		}
		seen.add(extension.type);
		previous = extension.type;
		return concat(uint(extension.type, 2), vector(extension.data, 2));
	});
	return vector(concat(...parts), 2);
}

function readExtensions(
	reader: Reader,
	max = 16383,
	sorted = false,
): Extension[] {
	const inner = new Reader(reader.vector(2));
	const result: Extension[] = [];
	while (inner.remaining) {
		if (result.length >= max)
			throw new DAPError("InvalidMessage", "Too many extensions");
		result.push({ type: inner.uint(2), data: inner.vector(2) });
	}
	encodeExtensions(result, sorted);
	return result;
}

export function encodeTaskConfiguration(task: TaskConfiguration): Uint8Array {
	return concat(
		vector(task.info, 1),
		vector(task.leader, 2, 1),
		vector(task.helper, 2, 1),
		uint(task.timePrecision, 8),
		uint(task.minBatchSize, 8),
		uint(task.batchMode, 1),
		vector(task.batchConfig, 2),
		uint(task.vdafType, 4),
		vector(task.vdafConfig, 2),
		encodeExtensions(task.extensions, true),
	);
}

export function decodeTaskConfiguration(
	input: Uint8Array,
	options: DecodeOptions = {},
): TaskConfiguration {
	const infoLimit = options.maxTaskInfoSize ?? 255;
	const extensionLimit = options.maxExtensions ?? 16383;
	for (const limit of [infoLimit, extensionLimit]) {
		if (!Number.isSafeInteger(limit) || limit < 0)
			throw new DAPError("InvalidMessage", "Invalid decode limit");
	}
	const reader = new Reader(input);
	const info = reader.vector(1);
	if (info.length > infoLimit)
		throw new DAPError("InvalidMessage", "Task info is too long");
	const result = {
		info,
		leader: reader.vector(2, 1),
		helper: reader.vector(2, 1),
		timePrecision: reader.u64(),
		minBatchSize: reader.u64(),
		batchMode: reader.uint(1),
		batchConfig: reader.vector(2),
		vdafType: reader.uint(4),
		vdafConfig: reader.vector(2),
		extensions: readExtensions(reader, extensionLimit, true),
	};
	reader.end();
	return result;
}

export function encodeHpkeConfigList(
	configs: readonly HpkeConfig[],
): Uint8Array {
	const result = vector(
		concat(
			...configs.map((config) =>
				concat(
					uint(config.id, 1),
					uint(config.kemId, 2),
					uint(config.kdfId, 2),
					uint(config.aeadId, 2),
					vector(config.publicKey, 2, 1),
				),
			),
		),
		2,
		10,
	);
	decodeHpkeConfigList(result);
	return result;
}

export function decodeHpkeConfigList(input: Uint8Array): HpkeConfig[] {
	const outer = new Reader(input);
	const reader = new Reader(outer.vector(2, 10));
	outer.end();
	const configs: HpkeConfig[] = [];
	const ids = new Set<number>();
	while (reader.remaining) {
		const id = reader.uint(1);
		if (ids.has(id))
			throw new DAPError("InvalidHpkeConfig", "Duplicate HPKE config ID");
		ids.add(id);
		configs.push({
			id,
			kemId: reader.uint(2),
			kdfId: reader.uint(2),
			aeadId: reader.uint(2),
			publicKey: reader.vector(2, 1),
		});
	}
	return configs;
}

export function encodeReportMetadata(metadata: ReportMetadata): Uint8Array {
	return concat(
		bytes(metadata.id, 16),
		uint(metadata.time, 8),
		encodeExtensions(metadata.publicExtensions),
	);
}

export function encodePlaintextInputShare(
	payload: Uint8Array,
	extensions: readonly Extension[] = [],
): Uint8Array {
	return concat(encodeExtensions(extensions), vector(payload, 4, 1));
}

export function encodeInputShareAad(
	taskId: Uint8Array,
	configuration: Uint8Array,
	metadata: ReportMetadata,
	publicShare: Uint8Array,
): Uint8Array {
	return concat(
		bytes(taskId, 32),
		configuration,
		encodeReportMetadata(metadata),
		vector(publicShare, 4),
	);
}

function encodeCiphertext(ciphertext: HpkeCiphertext): Uint8Array {
	return concat(
		uint(ciphertext.configId, 1),
		vector(ciphertext.enc, 2, 1),
		vector(ciphertext.payload, 4, 1),
	);
}

export function encodeReport(report: Report | PreparedReport): Uint8Array {
	if (isPreparedReport(report)) return reportBytes(report);
	return concat(
		encodeReportMetadata(report.metadata),
		vector(report.publicShare, 4),
		encodeCiphertext(report.leader),
		encodeCiphertext(report.helper),
	);
}

export function decodeReport(input: Uint8Array): Report {
	const reader = new Reader(input);
	const metadata = {
		id: reader.take(16),
		time: reader.u64(),
		publicExtensions: readExtensions(reader),
	};
	const publicShare = reader.vector(4);
	const readCiphertext = (): HpkeCiphertext => ({
		configId: reader.uint(1),
		enc: reader.vector(2, 1),
		payload: reader.vector(4, 1),
	});
	const result = {
		metadata,
		publicShare,
		leader: readCiphertext(),
		helper: readCiphertext(),
	};
	reader.end();
	return result;
}

export function encodeUploadRequest(
	reports: readonly (Report | PreparedReport | Uint8Array)[],
): Uint8Array {
	return concat(
		...reports.map((report) =>
			report instanceof Uint8Array ? report : encodeReport(report),
		),
	);
}

export function decodeUploadErrors(
	input: Uint8Array,
): { id: string; rawCode: number }[] {
	const reader = new Reader(input);
	const result: { id: string; rawCode: number }[] = [];
	while (reader.remaining) {
		const id = base64url(reader.take(16));
		const rawCode = reader.uint(1);
		if (rawCode === 0)
			throw new DAPError("InvalidMessage", "Reserved upload error code");
		result.push({ id, rawCode });
	}
	return result;
}
