import { sha256 } from "@noble/hashes/sha2.js";
import {
	addFieldOutputShare,
	histogramVerifierMessage,
	histogramVerifierShare,
	sumVerifierMessage,
	sumVerifierShare,
} from "./aggregator-prio3.js";
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
import { createSuite, HpkeConfigList, prepareRecipientKey } from "./hpke.js";
import {
	decodeAggregateShare,
	decodeAggregateShareRequest,
	decodeCollectionJobRequest,
	decodeReport,
	decodeUploadRequest,
	encodeAggregateShare,
	encodeAggregateShareRequest,
	encodeCollectionJobResponse,
	encodeHpkeConfigList,
	encodeInputShareAad,
	encodeReport,
	encodeUploadErrors,
	type HpkeCiphertext,
	type HpkeConfig,
	type Report,
	type ReportMetadata,
} from "./messages.js";
import { expand, mod, P, requireBytes } from "./prio3-count.js";
import { P128 } from "./prio3-histogram.js";
import {
	type ReportError,
	type ReportId,
	reportErrorCode,
	reportErrors,
} from "./reports.js";
import { Task, toMs, toTime } from "./task.js";
import { shareLength, type Vdaf } from "./vdaf.js";

const HALF = (P + 1n) / 2n;
const ROOT4 = 281474976710656n;
const suite = createSuite();

/** Seconds a report timestamp may lead an Aggregator's clock (DAP 19, 4.5.3.4). */
const DEFAULT_MAX_SKEW_SECONDS = 300;

function elements(input: Uint8Array, length: number): bigint[] {
	requireBytes(input, length * 8);
	const view = new DataView(input.buffer, input.byteOffset, input.byteLength);
	return Array.from({ length }, (_, i) => {
		const value = view.getBigUint64(i * 8, true);
		if (value >= P) throw new RangeError("Non-canonical Field64 element");
		return value;
	});
}

function encoded(values: bigint[]): Uint8Array {
	const output = new Uint8Array(values.length * 8);
	const view = new DataView(output.buffer);
	values.forEach((value, i) => {
		view.setBigUint64(i * 8, value, true);
	});
	return output;
}

/** Compute one aggregator's Prio3Count verifier share (VDAF draft 20, Section 7.3.3). */
export function countVerifierShare(
	aggregatorId: 0 | 1,
	verifyKey: Uint8Array,
	context: Uint8Array,
	nonce: Uint8Array,
	publicShare: Uint8Array,
	inputShare: Uint8Array,
): Uint8Array {
	if (aggregatorId !== 0 && aggregatorId !== 1)
		throw new RangeError("Invalid aggregator ID");
	requireBytes(verifyKey, 32);
	requireBytes(context);
	requireBytes(nonce, 16);
	requireBytes(publicShare, 0);
	requireBytes(inputShare, aggregatorId === 0 ? 48 : 32);
	const [point] = expand(verifyKey, context, 5, Uint8Array.of(1, ...nonce), 1);
	if (mod(point! * point!) === 1n) throw new RangeError("Invalid query point");
	const measurement =
		aggregatorId === 0
			? elements(inputShare.subarray(0, 8), 1)[0]!
			: expand(inputShare, context, 1, Uint8Array.of(1), 1)[0]!;
	const proof =
		aggregatorId === 0
			? elements(inputShare.subarray(8), 5)
			: expand(inputShare, context, 2, Uint8Array.of(1, 1), 5);
	const validity = mod(proof[4]! - measurement);
	const wire = [0, 1].map((i) =>
		mod((proof[i]! + measurement + (proof[i]! - measurement) * point!) * HALF),
	);
	// The gadget polynomial has degree two and evaluations at 1, i, and -1.
	// Direct interpolation avoids a per-report inverse NTT and modular powers.
	const slope = mod((proof[2]! - proof[4]!) * HALF);
	const ends = mod((proof[2]! + proof[4]!) * HALF);
	const quadratic = mod((ends + slope * ROOT4 - proof[3]!) * HALF);
	const gadget = mod((quadratic * point! + slope) * point! + ends - quadratic);
	return encoded([validity, ...wire, gadget]);
}

/** Check the two verifier shares. Count's verifier message is empty. */
export function countVerifierMessage(
	leaderShare: Uint8Array,
	helperShare: Uint8Array,
): Uint8Array {
	const a = elements(leaderShare, 4);
	const b = elements(helperShare, 4);
	const combined = a.map((value, i) => mod(value + b[i]!));
	if (combined[0] !== 0n || mod(combined[1]! * combined[2]!) !== combined[3]) {
		throw new RangeError("Prio3Count verification failed");
	}
	return new Uint8Array();
}

function pingPong(type: 0 | 2, payload: Uint8Array): Uint8Array {
	return concat(Uint8Array.of(type), vector(payload, 4));
}

function readPingPong(
	input: Uint8Array,
	type: 0 | 2,
	length: number,
): Uint8Array {
	const reader = new Reader(input);
	if (reader.uint(1) !== type)
		throw new RangeError("Unexpected ping-pong message");
	const payload = reader.vector(4);
	reader.end();
	requireBytes(payload, length);
	return payload;
}

/** Start the leader's one-round Count verification. Persist state until the helper responds. */
function leaderCountInit(
	verifyKey: Uint8Array,
	context: Uint8Array,
	nonce: Uint8Array,
	publicShare: Uint8Array,
	inputShare: Uint8Array,
): { state: Uint8Array; outbound: Uint8Array } {
	const share = countVerifierShare(
		0,
		verifyKey,
		context,
		nonce,
		publicShare,
		inputShare,
	);
	return { state: inputShare.slice(0, 8), outbound: pingPong(0, share) };
}

/** Verify the leader's Count share and produce the helper's output share. */
function helperCountInit(
	verifyKey: Uint8Array,
	context: Uint8Array,
	nonce: Uint8Array,
	publicShare: Uint8Array,
	inputShare: Uint8Array,
	inbound: Uint8Array,
): { outputShare: Uint8Array; outbound: Uint8Array } {
	const leaderShare = readPingPong(inbound, 0, 32);
	const helperShare = countVerifierShare(
		1,
		verifyKey,
		context,
		nonce,
		publicShare,
		inputShare,
	);
	const message = countVerifierMessage(leaderShare, helperShare);
	const outputShare = encoded([
		expand(inputShare, context, 1, Uint8Array.of(1), 1)[0]!,
	]);
	return { outputShare, outbound: pingPong(2, message) };
}

/** Finish Count verification after receiving the helper's authenticated response. */
function leaderCountFinish(state: Uint8Array, inbound: Uint8Array): Uint8Array {
	const outputShare = elements(state, 1);
	readPingPong(inbound, 2, 0);
	return encoded(outputShare);
}

/** A report the aggregation step rejected, with its DAP report error. */
class Rejection extends Error {
	readonly error: ReportError;
	constructor(error: ReportError) {
		super(error);
		this.error = error;
	}
}

function inputShareLength(vdaf: Vdaf, role: "leader" | "helper"): number {
	if (role === "helper") return vdaf.type === "prio3-histogram" ? 64 : 32;
	if (vdaf.type === "prio3-count") return 48;
	if (vdaf.type === "prio3-sum") {
		const bits = vdaf.maxMeasurement.toString(2).length;
		let p = 1;
		while (p <= bits) p *= 2;
		return 8 * (bits + 2 * p);
	}
	const calls = Math.ceil(vdaf.length / vdaf.chunkLength);
	let p = 1;
	while (p <= calls) p *= 2;
	return 16 * (vdaf.length + 2 * vdaf.chunkLength + 2 * p - 1) + 32;
}

/** The Leader's input share must hold canonical field elements. */
function checkLeaderShare(vdaf: Vdaf, share: Uint8Array): void {
	if (vdaf.type === "prio3-count") elements(share, 6);
	else if (vdaf.type === "prio3-sum") {
		for (let offset = 0; offset < share.length; offset += 8)
			elements(share.subarray(offset, offset + 8), 1);
	} else {
		const view = new DataView(share.buffer, share.byteOffset, share.byteLength);
		for (let offset = 0; offset < share.length - 32; offset += 16) {
			const value =
				view.getBigUint64(offset, true) |
				(view.getBigUint64(offset + 8, true) << 64n);
			if (value >= P128) throw new RangeError("Non-canonical Field128 element");
		}
	}
}

export interface AggregatorHpkeKey {
	readonly configId: number;
	/** Raw X25519 private key bytes. */
	readonly privateKey: Uint8Array;
}
export interface VerifyKey {
	readonly id: number;
	/** The 32-byte VDAF verification key shared by both Aggregators. */
	readonly key: Uint8Array;
}
export interface AggregatorOptions {
	/**
	 * Every HPKE key this Aggregator accepts, most preferred first. Keep
	 * retired keys here for twice the configuration's cache lifetime
	 * (DAP 19, 4.4.1).
	 */
	readonly hpkeKeys: readonly AggregatorHpkeKey[];
	/** Verification keys by ID. The Leader starts new jobs with the first. */
	readonly verifyKeys: readonly VerifyKey[];
	/** The task's collector HPKE configuration, needed to answer collections. */
	readonly collector?: HpkeConfig;
	/** Seconds a report timestamp may lead the clock. Defaults to 300. */
	readonly maxSkewSeconds?: number;
	/** Unix milliseconds, as returned by Date.now(). */
	readonly clock?: () => number;
}

/** A time interval in Unix milliseconds, start inclusive and end exclusive. */
export interface Interval {
	readonly start: number;
	readonly end: number;
}

export interface ReportRef {
	readonly id: ReportId;
	/** Unix milliseconds, truncated to the task's time precision. It names the report's batch bucket. */
	readonly time: number;
}
export interface ReportRejectionEntry {
	readonly id: ReportId;
	readonly error: ReportError;
}
/** One report's outcome. Commit `outputShare` to the bucket for `time`. */
export type AggregatedReport = ReportRef &
	(
		| { readonly outputShare: Uint8Array; readonly error?: never }
		| { readonly error: ReportError; readonly outputShare?: never }
	);

export interface UploadedReport extends ReportRef {
	/** The encoded report to store until it joins an aggregation job. */
	readonly report: Uint8Array<ArrayBuffer>;
}
export interface Upload {
	/** Reports that passed the upload checks. */
	readonly reports: readonly UploadedReport[];
	/** Reports the upload checks rejected. `respond()` includes them. */
	readonly rejected: readonly ReportRejectionEntry[];
	/**
	 * Build the UploadErrors body in request order, adding the host's own
	 * rejections, such as report-replayed or batch-collected. An empty body
	 * means every report was accepted.
	 */
	respond(rejected?: readonly ReportRejectionEntry[]): Uint8Array<ArrayBuffer>;
}
export interface AggregationJob {
	/** AggregationJobInitReq bytes, or undefined when no report survived. */
	readonly request: Uint8Array<ArrayBuffer> | undefined;
	/** Leader verification state. Persist with `request` before sending it. */
	readonly state: Uint8Array<ArrayBuffer>;
	readonly reports: readonly ReportRef[];
	/** Rejected before the job was built, so absent from `request`. */
	readonly rejected: readonly (ReportRef & { readonly error: ReportError })[];
}
export interface VerifiedJob {
	readonly reports: readonly AggregatedReport[];
	/**
	 * Build the AggregationJobResp body once the host has committed the
	 * accepted output shares. Pass the reports the host refused, such as
	 * report-replayed or batch-collected.
	 */
	seal(rejected?: readonly ReportRejectionEntry[]): Uint8Array<ArrayBuffer>;
}
export interface CollectionJob {
	readonly interval: Interval;
	/** The AggregateShareReq body for the merged bucket of `interval`. */
	aggregateShareRequest(bucket: Uint8Array): Uint8Array<ArrayBuffer>;
	/** The CollectionJobResp body, given the Helper's AggregateShare body. */
	finish(
		bucket: Uint8Array,
		helperResponse: Uint8Array,
	): Promise<Uint8Array<ArrayBuffer>>;
}
export interface AggregateShareJob {
	readonly interval: Interval;
	/** Check the merged bucket against the Leader's and seal the AggregateShare body. */
	finish(bucket: Uint8Array): Promise<Uint8Array<ArrayBuffer>>;
}

// A batch bucket (DAP 19, 4.5.4.3) is stored as one opaque value:
// aggregate share || report count (u64) || checksum (32) || first and last
// report time (u64 each), so a merged bucket also yields the collected interval.
const NO_TIME = 0xffff_ffff_ffff_ffffn;

interface Bucket {
	share: Uint8Array;
	count: bigint;
	checksum: Uint8Array;
	first: bigint;
	last: bigint;
}

abstract class Aggregator<V extends Vdaf> {
	readonly task: Task<V>;
	/** Serve this list at `{aggregator}/hpke_config`. */
	readonly hpkeConfigs: HpkeConfigList;
	#keys: ReadonlyMap<number, CryptoKeyPair>;
	#verifyKeys: ReadonlyMap<number, Uint8Array>;
	#firstVerifyKey: number;
	#collector: HpkeConfig | undefined;
	#maxSkew: number;
	#clock: () => number;
	#role: "leader" | "helper";

	protected constructor(
		role: "leader" | "helper",
		task: Task<V>,
		options: AggregatorOptions,
		keys: ReadonlyMap<number, CryptoKeyPair>,
		hpkeConfigs: HpkeConfigList,
	) {
		this.#role = role;
		this.task = task;
		this.#keys = keys;
		this.hpkeConfigs = hpkeConfigs;
		this.#verifyKeys = new Map(
			options.verifyKeys.map(({ id, key }) => [id, bytes(key, 32).slice()]),
		);
		this.#firstVerifyKey = options.verifyKeys[0]!.id;
		this.#collector = options.collector;
		this.#maxSkew = options.maxSkewSeconds ?? DEFAULT_MAX_SKEW_SECONDS;
		this.#clock = options.clock ?? Date.now;
	}

	/** Check options and import each HPKE key once. */
	protected static async load(
		task: Task,
		options: AggregatorOptions,
	): Promise<{ keys: Map<number, CryptoKeyPair>; configs: HpkeConfigList }> {
		if (!(task instanceof Task) || task.dapVersion !== 19)
			throw new DAPError("InvalidTask", "Expected a DAP 19 task");
		const ids = (list: readonly { readonly id: number }[] | undefined) => {
			if (!Array.isArray(list) || !list.length)
				throw new DAPError("InvalidHpkeConfig", "Expected at least one key");
			for (const { id } of list) uint(id, 1);
			if (new Set(list.map(({ id }) => id)).size !== list.length)
				throw new DAPError("InvalidHpkeConfig", "Duplicate key ID");
		};
		ids(options.hpkeKeys?.map(({ configId }) => ({ id: configId })));
		ids(options.verifyKeys);
		for (const { key } of options.verifyKeys) bytes(key, 32);
		const skew = options.maxSkewSeconds ?? DEFAULT_MAX_SKEW_SECONDS;
		if (!Number.isSafeInteger(skew) || skew < 0)
			throw new DAPError("InvalidMessage", "Invalid clock skew allowance");
		const collector = options.collector;
		if (
			collector &&
			(collector.kemId !== 32 ||
				collector.kdfId !== 1 ||
				collector.aeadId !== 1 ||
				bytes(collector.publicKey).length !== 32)
		)
			throw new DAPError(
				"UnsupportedCipherSuite",
				"Unsupported collector HPKE configuration",
			);
		if (collector) uint(collector.id, 1);
		const keys = new Map<number, CryptoKeyPair>();
		const configs: HpkeConfig[] = [];
		for (const { configId, privateKey } of options.hpkeKeys) {
			const { pair, publicKey } = await prepareRecipientKey(privateKey);
			keys.set(configId, pair);
			configs.push({ id: configId, kemId: 32, kdfId: 1, aeadId: 1, publicKey });
		}
		return {
			keys,
			configs: HpkeConfigList.parse(encodeHpkeConfigList(configs)),
		};
	}

	/** Commit one output share to a batch bucket. Pass undefined to start one. */
	addToBucket(
		bucket: Uint8Array | undefined,
		report: ReportRef & { readonly outputShare: Uint8Array },
	): Uint8Array<ArrayBuffer> {
		// Patch the fields in place: this runs once per committed report.
		const length = shareLength(this.task.vdaf);
		const out = bucket
			? bytes(bucket, length + 56).slice()
			: this.#writeBucket(this.#readBucket(undefined));
		const view = new DataView(out.buffer);
		const time = toTime(this.task, report.time);
		const digest = sha256(decodeId(report.id, 16));
		out.set(
			addFieldOutputShare(
				out.subarray(0, length),
				bytes(report.outputShare, length),
				this.task.vdaf.type === "prio3-histogram" ? 16 : 8,
			),
		);
		view.setBigUint64(length, view.getBigUint64(length) + 1n);
		for (let i = 0; i < 32; i++) out[length + 8 + i]! ^= digest[i]!;
		if (time < view.getBigUint64(length + 40))
			view.setBigUint64(length + 40, time);
		if (time > view.getBigUint64(length + 48))
			view.setBigUint64(length + 48, time);
		return out;
	}

	/** Combine the buckets of one batch (DAP 19, 4.6.4). */
	mergeBuckets(buckets: readonly Uint8Array[]): Uint8Array<ArrayBuffer> {
		let result = this.#readBucket(undefined);
		for (const encoded of buckets) {
			const next = this.#readBucket(encoded);
			result = {
				share: addFieldOutputShare(
					result.share,
					next.share,
					this.task.vdaf.type === "prio3-histogram" ? 16 : 8,
				),
				count: result.count + next.count,
				checksum: result.checksum.map((byte, i) => byte ^ next.checksum[i]!),
				first: next.first < result.first ? next.first : result.first,
				last: next.last > result.last ? next.last : result.last,
			};
		}
		return this.#writeBucket(result);
	}

	bucketReportCount(bucket: Uint8Array): number {
		return Number(this.#readBucket(bucket).count);
	}

	#readBucket(bucket: Uint8Array | undefined): Bucket {
		const length = shareLength(this.task.vdaf);
		if (!bucket)
			return {
				share: new Uint8Array(length),
				count: 0n,
				checksum: new Uint8Array(32),
				first: NO_TIME,
				last: 0n,
			};
		const reader = new Reader(bytes(bucket));
		const value = {
			share: reader.take(length),
			count: reader.u64(),
			checksum: reader.take(32),
			first: reader.u64(),
			last: reader.u64(),
		};
		reader.end();
		return value;
	}

	#writeBucket(bucket: Bucket): Uint8Array<ArrayBuffer> {
		return concat(
			bucket.share,
			uint(bucket.count, 8),
			bucket.checksum,
			uint(bucket.first, 8),
			uint(bucket.last, 8),
		);
	}

	/** The interval a merged bucket's reports span, in DAP time units. */
	protected bucketInterval(bucket: Uint8Array): {
		start: bigint;
		duration: bigint;
	} {
		const { first, last, count } = this.#readBucket(bucket);
		if (!count) throw new DAPError("InvalidMessage", "Empty batch bucket");
		return { start: first, duration: last - first + 1n };
	}

	protected bucketChecksum(bucket: Uint8Array): Uint8Array {
		return this.#readBucket(bucket).checksum;
	}

	protected bucketShare(bucket: Uint8Array): Uint8Array {
		return this.#readBucket(bucket).share;
	}

	protected get firstVerifyKey(): { id: number; key: Uint8Array } {
		return {
			id: this.#firstVerifyKey,
			key: this.#verifyKeys.get(this.#firstVerifyKey)!,
		};
	}

	protected verifyKey(id: number): Uint8Array | undefined {
		return this.#verifyKeys.get(id);
	}

	protected knowsConfig(id: number): boolean {
		return this.#keys.has(id);
	}

	/** Report times more than the skew allowance ahead of the clock are too early. */
	protected tooEarly(time: bigint): boolean {
		const now = this.#clock();
		if (!Number.isSafeInteger(now) || now < 0)
			throw new DAPError("InvalidMessage", "Invalid current time");
		return (
			time * BigInt(this.task.timePrecision) >
			BigInt(Math.floor(now / 1000)) + BigInt(this.#maxSkew)
		);
	}

	protected interval(start: bigint, duration: bigint): Interval {
		try {
			return {
				start: toMs(this.task, start),
				end: toMs(this.task, start + duration),
			};
		} catch (cause) {
			throw new DAPError("InvalidMessage", "Batch interval is out of range", {
				cause,
				type: "batchInvalid",
			});
		}
	}

	protected minimumBatch(count: bigint): void {
		if (count < BigInt(this.task.minBatchSize))
			throw new DAPError(
				"InvalidMessage",
				"Batch is smaller than the minimum",
				{
					type: "invalidBatchSize",
				},
			);
	}

	/** Decrypt and validate one input share (DAP 19, 4.5.3.3 and 4.5.3.4). */
	protected async open(
		metadata: ReportMetadata,
		publicShare: Uint8Array,
		ciphertext: HpkeCiphertext,
	): Promise<Uint8Array> {
		const vdaf = this.task.vdaf;
		const key = this.#keys.get(ciphertext.configId);
		if (!key) throw new Rejection("hpke-unknown-config-id");
		if (
			publicShare.length !== (vdaf.type === "prio3-histogram" ? 64 : 0) ||
			metadata.publicExtensions.length
		)
			throw new Rejection("invalid-message");
		if (this.tooEarly(metadata.time)) throw new Rejection("report-too-early");
		if (!this.task.inInterval(metadata.time))
			throw new Rejection("report-dropped");
		const aad = encodeInputShareAad(
			decodeId(this.task.id, 32),
			this.task.encodeConfiguration(),
			metadata,
			publicShare,
		);
		const info = concat(
			new TextEncoder().encode("dap-19 input share"),
			Uint8Array.of(1, this.#role === "leader" ? 2 : 3),
		);
		let plaintext: Uint8Array;
		try {
			plaintext = await suite.Open(key, ciphertext.enc, ciphertext.payload, {
				info,
				aad,
			});
		} catch {
			throw new Rejection("hpke-decrypt-error");
		}
		try {
			const reader = new Reader(plaintext);
			if (reader.vector(2).length) throw new RangeError("Private extension");
			const share = reader.vector(4, 1);
			reader.end();
			bytes(share, inputShareLength(vdaf, this.#role));
			if (this.#role === "leader") checkLeaderShare(vdaf, share);
			return share;
		} catch {
			throw new Rejection("invalid-message");
		}
	}

	/** Seal an aggregate share to the collector (DAP 19, 4.6.7). */
	protected async sealShare(
		collectionRequest: Uint8Array,
		share: Uint8Array,
	): Promise<HpkeCiphertext> {
		const collector = this.#collector;
		if (!collector)
			throw new DAPError("InvalidTask", "No collector HPKE configuration");
		const sealed = await suite.Seal(
			await suite.DeserializePublicKey(collector.publicKey),
			share,
			{
				info: concat(
					new TextEncoder().encode("dap-19 aggregate share"),
					Uint8Array.of(this.#role === "leader" ? 2 : 3, 0),
				),
				aad: concat(
					decodeId(this.task.id, 32),
					this.task.encodeConfiguration(),
					collectionRequest,
				),
			},
		);
		return {
			configId: collector.id,
			enc: sealed.encapsulatedSecret,
			payload: sealed.ciphertext,
		};
	}
}

function jobHeader(verificationKeyId: number): Uint8Array {
	return concat(
		uint(verificationKeyId, 1),
		vector(new Uint8Array(), 4),
		vector(new Uint8Array(), 2),
	);
}

function reject(id: Uint8Array, error: ReportError): Uint8Array {
	return concat(id, uint(2, 1), uint(reportErrorCode(error), 1));
}

export class Leader<V extends Vdaf = Vdaf> extends Aggregator<V> {
	private constructor(
		task: Task<V>,
		options: AggregatorOptions,
		keys: ReadonlyMap<number, CryptoKeyPair>,
		configs: HpkeConfigList,
	) {
		super("leader", task, options, keys, configs);
		Object.freeze(this);
	}

	static async create<V extends Vdaf>(
		task: Task<V>,
		options: AggregatorOptions,
	): Promise<Leader<V>> {
		const { keys, configs } = await Aggregator.load(task, options);
		return new Leader(task, options, keys, configs);
	}

	/**
	 * Check an UploadReq body (DAP 19, 4.4.2.2) without decrypting it. The
	 * host still checks replay and collected buckets before storing reports.
	 */
	upload(body: Uint8Array): Upload {
		const decoded = decodeUploadRequest(body);
		const statuses: (ReportError | undefined)[] = [];
		const first = new Map<string, number>();
		const reports: UploadedReport[] = [];
		const rejected: ReportRejectionEntry[] = [];
		for (const [index, report] of decoded.entries()) {
			const id = base64url(report.metadata.id) as ReportId;
			const error: ReportError | undefined = first.has(id)
				? "report-replayed"
				: report.metadata.publicExtensions.length
					? "unsupported-extension"
					: !this.knowsConfig(report.leader.configId)
						? "hpke-unknown-config-id"
						: this.tooEarly(report.metadata.time)
							? "report-too-early"
							: !this.task.inInterval(report.metadata.time)
								? "report-dropped"
								: undefined;
			if (!first.has(id)) first.set(id, index);
			statuses.push(error);
			if (error) rejected.push(Object.freeze({ id, error }));
			else
				reports.push(
					Object.freeze({
						id,
						time: toMs(this.task, report.metadata.time),
						report: encodeReport(report),
					}),
				);
		}
		return Object.freeze({
			reports: Object.freeze(reports),
			rejected: Object.freeze(rejected),
			respond: (extra: readonly ReportRejectionEntry[] = []) => {
				const all = statuses.slice();
				for (const { id, error } of extra) {
					const index = first.get(id);
					if (index === undefined || all[index])
						throw new DAPError(
							"InvalidMessage",
							"Rejection does not match an accepted report",
						);
					reportErrorCode(error);
					all[index] = error;
				}
				return encodeUploadErrors(
					decoded.flatMap((report, index) => {
						const error = all[index];
						return error ? [{ id: base64url(report.metadata.id), error }] : [];
					}),
				);
			},
		});
	}

	/**
	 * Decrypt and verify stored reports locally and build one
	 * AggregationJobInitReq. The host must first have checked replay and
	 * collected buckets for each report (DAP 19, 4.5.3.1).
	 */
	async prepare(reports: readonly Uint8Array[]): Promise<AggregationJob> {
		if (!reports.length)
			throw new DAPError("InvalidMessage", "Expected at least one report");
		const { id: keyId, key } = this.firstVerifyKey;
		const seen = new Set<string>();
		const ready: ReportRef[] = [];
		const rejected: (ReportRef & { error: ReportError })[] = [];
		const requestParts: Uint8Array[] = [];
		const stateParts: Uint8Array[] = [];
		for (const encoded of reports) {
			const report: Report = decodeReport(encoded);
			const id = base64url(report.metadata.id) as ReportId;
			if (seen.has(id))
				throw new DAPError("InvalidMessage", "Duplicate report ID in job");
			seen.add(id);
			let time: number;
			try {
				time = toMs(this.task, report.metadata.time);
			} catch {
				rejected.push({ id, time: 0, error: "report-too-early" });
				continue;
			}
			let init: { state: Uint8Array; outbound: Uint8Array };
			try {
				const input = await this.open(
					report.metadata,
					report.publicShare,
					report.leader,
				);
				try {
					init = leaderPrio3Init(
						this.task.vdaf,
						context(this.task),
						key,
						report.metadata.id,
						report.publicShare,
						input,
					);
				} catch {
					throw new Rejection("vdaf-verify-error");
				}
			} catch (error) {
				if (!(error instanceof Rejection)) throw error;
				rejected.push(Object.freeze({ id, time, error: error.error }));
				continue;
			}
			ready.push(Object.freeze({ id, time }));
			stateParts.push(
				report.metadata.id,
				uint(report.metadata.time, 8),
				vector(init.state, 4),
			);
			requestParts.push(
				concat(
					report.metadata.id,
					uint(report.metadata.time, 8),
					vector(new Uint8Array(), 2),
					vector(report.publicShare, 4),
					uint(report.helper.configId, 1),
					vector(report.helper.enc, 2, 1),
					vector(report.helper.payload, 4, 1),
					vector(init.outbound, 4, 1),
				),
			);
		}
		return Object.freeze({
			request: ready.length
				? concatParts([jobHeader(keyId), ...requestParts])
				: undefined,
			state: concatParts(stateParts),
			reports: Object.freeze(ready),
			rejected: Object.freeze(rejected),
		});
	}

	/**
	 * Finish from saved state once the Helper's AggregationJobResp arrives. A
	 * response that does not line up with the job throws, and the Leader
	 * must abandon the job (DAP 19, 4.5.3.1).
	 */
	finish(state: Uint8Array, response: Uint8Array): AggregatedReport[] {
		const saved = new Reader(bytes(state));
		const reader = new Reader(bytes(response));
		const results: AggregatedReport[] = [];
		try {
			while (saved.remaining) {
				const id = saved.take(16);
				const time = saved.u64();
				const verifier = saved.vector(4);
				const ref = {
					id: base64url(id) as ReportId,
					time: toMs(this.task, time),
				};
				if (!reader.take(16).every((byte, i) => byte === id[i]))
					throw new RangeError("Wrong report ID");
				const type = reader.uint(1);
				if (type === 2) {
					const error = reportErrors[reader.uint(1)];
					if (!error) throw new RangeError("Unknown report error");
					results.push(Object.freeze({ ...ref, error }));
				} else if (type === 0) {
					const outputShare = leaderPrio3Finish(
						this.task.vdaf,
						verifier,
						reader.vector(4, 1),
					);
					results.push(Object.freeze({ ...ref, outputShare }));
				} else throw new RangeError("Unexpected response type");
			}
			reader.end();
		} catch (cause) {
			throw new DAPError(
				"InvalidResponse",
				"Aggregation response does not match the job",
				{ cause },
			);
		}
		return results;
	}

	/**
	 * Validate a CollectionJobReq (DAP 19, 4.6.1). The host checks that the
	 * interval's buckets are not collected yet and have no pending jobs,
	 * then merges them.
	 */
	collection(body: Uint8Array): CollectionJob {
		const request = bytes(body).slice();
		const query = decodeCollectionJobRequest(request);
		const interval = this.interval(query.start, query.duration);
		return Object.freeze({
			interval,
			aggregateShareRequest: (bucket: Uint8Array) => {
				const count = BigInt(this.bucketReportCount(bucket));
				this.minimumBatch(count);
				return encodeAggregateShareRequest(
					request,
					count,
					this.bucketChecksum(bucket),
				);
			},
			finish: async (bucket: Uint8Array, helperResponse: Uint8Array) => {
				const count = BigInt(this.bucketReportCount(bucket));
				this.minimumBatch(count);
				let helper: HpkeCiphertext;
				try {
					helper = decodeAggregateShare(helperResponse);
				} catch (cause) {
					throw new DAPError("InvalidResponse", "Malformed aggregate share", {
						cause,
					});
				}
				const span = this.bucketInterval(bucket);
				return encodeCollectionJobResponse({
					reportCount: count,
					start: span.start,
					duration: span.duration,
					leader: await this.sealShare(request, this.bucketShare(bucket)),
					helper,
				});
			},
		});
	}
}

export class Helper<V extends Vdaf = Vdaf> extends Aggregator<V> {
	private constructor(
		task: Task<V>,
		options: AggregatorOptions,
		keys: ReadonlyMap<number, CryptoKeyPair>,
		configs: HpkeConfigList,
	) {
		super("helper", task, options, keys, configs);
		Object.freeze(this);
	}

	static async create<V extends Vdaf>(
		task: Task<V>,
		options: AggregatorOptions,
	): Promise<Helper<V>> {
		const { keys, configs } = await Aggregator.load(task, options);
		return new Helper(task, options, keys, configs);
	}

	/**
	 * Verify an AggregationJobInitReq (DAP 19, 4.5.3.2). Commit the accepted
	 * output shares, then call `seal()`.
	 */
	async verify(request: Uint8Array): Promise<VerifiedJob> {
		const reader = new Reader(bytes(request));
		const keyId = reader.uint(1);
		if (reader.vector(4).length)
			throw new DAPError(
				"InvalidMessage",
				"Prio3 takes no aggregation parameter",
				{
					type: "invalidAggregationParameter",
				},
			);
		if (reader.vector(2).length)
			throw new DAPError(
				"InvalidMessage",
				"Unsupported aggregation job extension",
				{
					type: "unsupportedExtension",
				},
			);
		const entries = [];
		const seen = new Set<string>();
		while (reader.remaining) {
			const metadata = { id: reader.take(16), time: reader.u64() };
			const id = base64url(metadata.id) as ReportId;
			if (seen.has(id))
				throw new DAPError("InvalidMessage", "Duplicate report ID in job");
			seen.add(id);
			entries.push({
				id,
				metadata: { ...metadata, publicExtensions: [] },
				publicExtensions: reader.vector(2).length,
				publicShare: reader.vector(4),
				ciphertext: {
					configId: reader.uint(1),
					enc: reader.vector(2, 1),
					payload: reader.vector(4, 1),
				},
				inbound: reader.vector(4, 1),
			});
		}
		if (!entries.length)
			throw new DAPError("InvalidMessage", "Empty aggregation job");
		const verifyKey = this.verifyKey(keyId);
		const results: (AggregatedReport & { response?: Uint8Array })[] = [];
		for (const entry of entries) {
			let time: number;
			try {
				time = toMs(this.task, entry.metadata.time);
			} catch {
				results.push({ id: entry.id, time: 0, error: "report-too-early" });
				continue;
			}
			try {
				if (!verifyKey) throw new Rejection("unknown-verification-key-id");
				if (entry.publicExtensions) throw new Rejection("invalid-message");
				const input = await this.open(
					entry.metadata,
					entry.publicShare,
					entry.ciphertext,
				);
				let step: { outputShare: Uint8Array; outbound: Uint8Array };
				try {
					step = helperPrio3Init(
						this.task.vdaf,
						context(this.task),
						verifyKey,
						entry.metadata.id,
						entry.publicShare,
						input,
						entry.inbound,
					);
				} catch {
					throw new Rejection("vdaf-verify-error");
				}
				results.push({
					id: entry.id,
					time,
					outputShare: step.outputShare,
					response: concat(
						entry.metadata.id,
						uint(0, 1),
						vector(step.outbound, 4, 1),
					),
				});
			} catch (error) {
				if (!(error instanceof Rejection)) throw error;
				results.push({ id: entry.id, time, error: error.error });
			}
		}
		return Object.freeze({
			reports: Object.freeze(
				results.map(({ response: _, ...report }) => Object.freeze(report)),
			) as readonly AggregatedReport[],
			seal: (refused: readonly ReportRejectionEntry[] = []) => {
				const errors = new Map<string, ReportError>();
				for (const { id, error } of refused) {
					reportErrorCode(error);
					if (!seen.has(id) || errors.has(id))
						throw new DAPError(
							"InvalidMessage",
							"Rejection does not match a report in the job",
						);
					errors.set(id, error);
				}
				return concatParts(
					results.map((report) => {
						const id = decodeId(report.id, 16);
						const error = errors.get(report.id) ?? report.error;
						return error ? reject(id, error) : report.response!;
					}),
				);
			},
		});
	}

	/**
	 * Validate an AggregateShareReq (DAP 19, 4.6.4). The host checks that the
	 * interval's buckets are not collected yet, then merges them.
	 */
	aggregateShare(body: Uint8Array): AggregateShareJob {
		const request = decodeAggregateShareRequest(bytes(body));
		const interval = this.interval(request.start, request.duration);
		return Object.freeze({
			interval,
			finish: async (bucket: Uint8Array) => {
				const count = BigInt(this.bucketReportCount(bucket));
				this.minimumBatch(count);
				const checksum = this.bucketChecksum(bucket);
				if (
					count !== request.reportCount ||
					!checksum.every((byte, i) => byte === request.checksum[i])
				)
					throw new DAPError(
						"InvalidMessage",
						"Aggregators disagree on the batch",
						{ type: "batchMismatch" },
					);
				return encodeAggregateShare(
					await this.sealShare(
						request.collectionRequest,
						this.bucketShare(bucket),
					),
				);
			},
		});
	}
}
function context(task: Task): Uint8Array {
	return concat(new TextEncoder().encode("dap-19"), decodeId(task.id, 32));
}

/** Start the Leader's one-round Prio3 verification. Persist state until the Helper responds. */
export function leaderPrio3Init(
	vdaf: Vdaf,
	ctx: Uint8Array,
	verifyKey: Uint8Array,
	nonce: Uint8Array,
	publicShare: Uint8Array,
	inputShare: Uint8Array,
): { state: Uint8Array; outbound: Uint8Array } {
	if (vdaf.type === "prio3-count")
		return leaderCountInit(verifyKey, ctx, nonce, publicShare, inputShare);
	if (vdaf.type === "prio3-sum") {
		const share = sumVerifierShare(
			0,
			vdaf.maxMeasurement,
			verifyKey,
			ctx,
			nonce,
			publicShare,
			inputShare,
		);
		return {
			state: share.outputShare,
			outbound: pingPong(0, share.verifierShare),
		};
	}
	const share = histogramVerifierShare(
		0,
		vdaf.length,
		vdaf.chunkLength,
		verifyKey,
		ctx,
		nonce,
		publicShare,
		inputShare,
	);
	return {
		state: concat(share.outputShare, share.jointSeed),
		outbound: pingPong(0, share.verifierShare),
	};
}

/** Verify the Leader's Prio3 share and produce the Helper's output share. */
export function helperPrio3Init(
	vdaf: Vdaf,
	ctx: Uint8Array,
	verifyKey: Uint8Array,
	nonce: Uint8Array,
	publicShare: Uint8Array,
	inputShare: Uint8Array,
	inbound: Uint8Array,
): { outputShare: Uint8Array; outbound: Uint8Array } {
	if (vdaf.type === "prio3-count")
		return helperCountInit(
			verifyKey,
			ctx,
			nonce,
			publicShare,
			inputShare,
			inbound,
		);
	if (vdaf.type === "prio3-sum") {
		const leaderShare = readPingPong(inbound, 0, 24);
		const helper = sumVerifierShare(
			1,
			vdaf.maxMeasurement,
			verifyKey,
			ctx,
			nonce,
			publicShare,
			inputShare,
		);
		return {
			outputShare: helper.outputShare,
			outbound: pingPong(
				2,
				sumVerifierMessage(leaderShare, helper.verifierShare),
			),
		};
	}
	const chunkLength = vdaf.chunkLength;
	const leaderShare = readPingPong(inbound, 0, (2 * chunkLength + 2) * 16 + 32);
	const helper = histogramVerifierShare(
		1,
		vdaf.length,
		chunkLength,
		verifyKey,
		ctx,
		nonce,
		publicShare,
		inputShare,
	);
	const message = histogramVerifierMessage(
		leaderShare,
		helper.verifierShare,
		chunkLength,
		ctx,
	);
	if (!message.every((byte, i) => byte === helper.jointSeed[i]))
		throw new RangeError("Prio3Histogram joint randomness mismatch");
	return { outputShare: helper.outputShare, outbound: pingPong(2, message) };
}

/** Finish Prio3 verification with the Helper's response. */
export function leaderPrio3Finish(
	vdaf: Vdaf,
	state: Uint8Array,
	inbound: Uint8Array,
): Uint8Array {
	if (vdaf.type === "prio3-count") return leaderCountFinish(state, inbound);
	if (vdaf.type === "prio3-sum") {
		bytes(state, 8);
		readPingPong(inbound, 2, 0);
		return state.slice();
	}
	const length = vdaf.length * 16;
	bytes(state, length + 32);
	const message = readPingPong(inbound, 2, 32);
	if (!message.every((byte, i) => byte === state[length + i]))
		throw new RangeError("Prio3Histogram joint randomness mismatch");
	return state.slice(0, length);
}
