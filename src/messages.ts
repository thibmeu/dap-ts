import {
	base64url,
	bytes,
	concat,
	concatParts,
	decodeId,
	Reader,
	uint,
	vector,
} from "./binary.js";
import { DAPError } from "./errors.js";
import {
	isPreparedReport,
	type PreparedReport,
	type ReportError,
	reportBytes,
	reportErrorCode,
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

export interface CollectionJobResponse {
	readonly reportCount: bigint;
	readonly start: bigint;
	readonly duration: bigint;
	readonly leader: HpkeCiphertext;
	readonly helper: HpkeCiphertext;
}

/** The supported Prio3 VDAFs have empty aggregation parameters and collection extensions. */
export function encodeCollectionJobRequest(
	start: number | bigint,
	duration: number | bigint,
): Uint8Array<ArrayBuffer> {
	const encodedStart = uint(start, 8);
	const encodedDuration = uint(duration, 8);
	if (
		BigInt(duration) === 0n ||
		BigInt(start) + BigInt(duration) > 0xffffffffffffffffn
	)
		throw new DAPError("InvalidMessage", "Invalid collection interval");
	return concat(
		uint(1, 1),
		vector(concat(encodedStart, encodedDuration), 2),
		vector(new Uint8Array(), 4),
		vector(new Uint8Array(), 2),
	);
}

export function decodeCollectionJobRequest(input: Uint8Array): {
	start: bigint;
	duration: bigint;
} {
	const reader = new Reader(input);
	if (reader.uint(1) !== 1)
		throw new DAPError("InvalidMessage", "Expected time-interval query");
	const query = new Reader(reader.vector(2));
	const start = query.u64();
	const duration = query.u64();
	query.end();
	if (reader.vector(4).length || reader.vector(2).length)
		throw new DAPError(
			"InvalidMessage",
			"Expected empty count parameter and extensions",
		);
	reader.end();
	if (duration === 0n || start + duration > 0xffffffffffffffffn)
		throw new DAPError("InvalidMessage", "Invalid collection interval");
	return { start, duration };
}

export function decodeCollectionJobResponse(
	input: Uint8Array,
): CollectionJobResponse {
	const reader = new Reader(input);
	const reportCount = reader.u64();
	const start = reader.u64();
	const duration = reader.u64();
	const ciphertext = (): HpkeCiphertext => ({
		configId: reader.uint(1),
		enc: reader.vector(2, 1),
		payload: reader.vector(4, 1),
	});
	const result = {
		reportCount,
		start,
		duration,
		leader: ciphertext(),
		helper: ciphertext(),
	};
	reader.end();
	if (duration === 0n || start + duration > 0xffffffffffffffffn)
		throw new DAPError("InvalidMessage", "Invalid collection interval");
	return result;
}

export function encodeCollectionJobResponse(
	value: CollectionJobResponse,
): Uint8Array<ArrayBuffer> {
	return concat(
		uint(value.reportCount, 8),
		uint(value.start, 8),
		uint(value.duration, 8),
		encodeCiphertext(value.leader),
		encodeCiphertext(value.helper),
	);
}

export function encodeAggregateShareRequest(
	collectionRequest: Uint8Array,
	reportCount: number | bigint,
	checksum: Uint8Array,
): Uint8Array<ArrayBuffer> {
	const { start, duration } = decodeCollectionJobRequest(collectionRequest);
	return concat(
		collectionRequest,
		uint(1, 1),
		vector(concat(uint(start, 8), uint(duration, 8)), 2),
		uint(reportCount, 8),
		bytes(checksum, 32),
	);
}

export function decodeAggregateShareRequest(input: Uint8Array): {
	collectionRequest: Uint8Array;
	start: bigint;
	duration: bigint;
	reportCount: bigint;
	checksum: Uint8Array;
} {
	const reader = new Reader(input);
	const collectionRequest = reader.take(25);
	const { start, duration } = decodeCollectionJobRequest(collectionRequest);
	if (reader.uint(1) !== 1)
		throw new DAPError(
			"InvalidMessage",
			"Expected time-interval batch selector",
		);
	const selector = new Reader(reader.vector(2));
	const selectedStart = selector.u64();
	const selectedDuration = selector.u64();
	selector.end();
	const reportCount = reader.u64();
	const checksum = reader.take(32);
	reader.end();
	// DAP 19, 5.1.2: the selected interval must lie within the query.
	if (
		selectedDuration === 0n ||
		selectedStart < start ||
		selectedStart + selectedDuration > start + duration
	)
		throw new DAPError("InvalidMessage", "Batch selector does not match query");
	return {
		collectionRequest,
		start: selectedStart,
		duration: selectedDuration,
		reportCount,
		checksum,
	};
}

export function encodeAggregateShare(
	ciphertext: HpkeCiphertext,
): Uint8Array<ArrayBuffer> {
	return encodeCiphertext(ciphertext);
}

export function decodeAggregateShare(input: Uint8Array): HpkeCiphertext {
	const reader = new Reader(input);
	const value = {
		configId: reader.uint(1),
		enc: reader.vector(2, 1),
		payload: reader.vector(4, 1),
	};
	reader.end();
	return value;
}

export function encodeExtensions(
	extensions: readonly Extension[],
	sorted = false,
): Uint8Array<ArrayBuffer> {
	const seen = new Set<number>();
	let previous = -1;
	let size = 0;
	const parts = extensions.map((extension) => {
		size += 4 + bytes(extension.data).length;
		if (size > 65535)
			throw new DAPError("InvalidMessage", "Extensions exceed the size limit");
		if (seen.has(extension.type) || (sorted && extension.type <= previous)) {
			throw new DAPError("InvalidMessage", "Duplicate or unordered extension");
		}
		seen.add(extension.type);
		previous = extension.type;
		return concat(uint(extension.type, 2), vector(extension.data, 2));
	});
	return vector(concatParts(parts), 2);
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

export function encodeTaskConfiguration(
	task: TaskConfiguration,
): Uint8Array<ArrayBuffer> {
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
): Uint8Array<ArrayBuffer> {
	if (configs.length > 256)
		throw new DAPError("InvalidHpkeConfig", "Too many HPKE configurations");
	const result = vector(
		concatParts(
			configs.map((config) =>
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

export function encodeReportMetadata(
	metadata: ReportMetadata,
): Uint8Array<ArrayBuffer> {
	return concat(
		bytes(metadata.id, 16),
		uint(metadata.time, 8),
		encodeExtensions(metadata.publicExtensions),
	);
}

export function encodePlaintextInputShare(
	payload: Uint8Array,
	extensions: readonly Extension[] = [],
): Uint8Array<ArrayBuffer> {
	return concat(encodeExtensions(extensions), vector(payload, 4, 1));
}

export function encodeInputShareAad(
	taskId: Uint8Array,
	configuration: Uint8Array,
	metadata: ReportMetadata,
	publicShare: Uint8Array,
): Uint8Array<ArrayBuffer> {
	return concat(
		bytes(taskId, 32),
		configuration,
		encodeReportMetadata(metadata),
		vector(publicShare, 4),
	);
}

function encodeCiphertext(ciphertext: HpkeCiphertext): Uint8Array<ArrayBuffer> {
	return concat(
		uint(ciphertext.configId, 1),
		vector(ciphertext.enc, 2, 1),
		vector(ciphertext.payload, 4, 1),
	);
}

export function encodeReport(
	report: Report | PreparedReport,
): Uint8Array<ArrayBuffer> {
	if (isPreparedReport(report)) return reportBytes(report);
	return concat(
		encodeReportMetadata(report.metadata),
		vector(report.publicShare, 4),
		encodeCiphertext(report.leader),
		encodeCiphertext(report.helper),
	);
}

function readReport(reader: Reader): Report {
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
	return result;
}

export function decodeReport(input: Uint8Array): Report {
	const reader = new Reader(input);
	const result = readReport(reader);
	reader.end();
	return result;
}

export function decodeUploadRequest(input: Uint8Array): Report[] {
	const reader = new Reader(input);
	const reports: Report[] = [];
	while (reader.remaining) reports.push(readReport(reader));
	if (!reports.length)
		throw new DAPError("InvalidMessage", "Expected at least one report");
	return reports;
}

export function encodeUploadRequest(
	reports: readonly (Report | PreparedReport | Uint8Array)[],
): Uint8Array<ArrayBuffer> {
	return concatParts(
		reports.map((report) =>
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

/** Encode UploadErrors (DAP 19, 4.4.2.2) in the order given. */
export function encodeUploadErrors(
	errors: readonly { readonly id: string; readonly error: ReportError }[],
): Uint8Array<ArrayBuffer> {
	return concatParts(
		errors.map(({ id, error }) =>
			concat(decodeId(id, 16), uint(reportErrorCode(error), 1)),
		),
	);
}
