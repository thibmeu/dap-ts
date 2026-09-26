import { base64url, bytes, concat, concatParts, decodeId } from "./binary.js";
import { DAPError } from "./errors.js";
import {
	type AggregatorHpkeConfigs,
	createSuite,
	type RandomSource,
	randomBytes,
	secureRandom,
	selectConfig,
} from "./hpke.js";
import {
	decodeUploadErrors,
	type Extension,
	encodeInputShareAad,
	encodePlaintextInputShare,
	encodeReport,
	type HpkeConfig,
} from "./messages.js";
import { shardCountWithRandomness } from "./prio3-count.js";
import {
	shardHistogramWithRandomness,
	validateHistogramMeasurement,
} from "./prio3-histogram.js";
import { shardSumWithRandomness, validateSumMeasurement } from "./prio3-sum.js";
import {
	type PreparedReport,
	preparedReport,
	type ReportId,
	reportBytes,
} from "./reports.js";
import { Task } from "./task.js";

export interface DAPRequest {
	readonly method: "GET" | "POST";
	readonly url: string;
	readonly headers: Readonly<Record<string, string>>;
	readonly body?: Uint8Array;
}
export interface DAPResponse {
	readonly status: number;
	readonly headers: Readonly<Record<string, string>>;
	readonly body: Uint8Array;
}
export interface ReportRejection {
	readonly id: ReportId;
	readonly code:
		| "batch-collected"
		| "report-replayed"
		| "report-dropped"
		| "hpke-unknown-config-id"
		| "hpke-decrypt-error"
		| "vdaf-verify-error"
		| "invalid-message"
		| "report-too-early"
		| "unknown-verification-key-id"
		| "unsupported-extension"
		| "unknown";
	readonly rawCode: number;
}
export interface UploadResult {
	readonly accepted: readonly ReportId[];
	readonly rejected: readonly ReportRejection[];
	readonly ok: boolean;
}
export interface PreparedUpload {
	readonly request: DAPRequest;
	process(response: DAPResponse): UploadResult;
}
export interface ClientOptions {
	readonly hpke: AggregatorHpkeConfigs;
	readonly random?: RandomSource;
	/** Unix milliseconds, as returned by Date.now(). */
	readonly clock?: () => number;
}
export interface PrepareReportOptions {
	/** Date or Unix milliseconds. */
	readonly time?: Date | number;
	readonly publicExtensions?: readonly Extension[];
	readonly privateExtensions?: {
		readonly leader?: readonly Extension[];
		readonly helper?: readonly Extension[];
	};
}

export function resource(base: string, path: string): string {
	return `${base.endsWith("/") ? base : `${base}/`}${path}`;
}

export function header(
	headers: Readonly<Record<string, string>>,
	name: string,
): string | undefined {
	const matches = Object.entries(headers).filter(
		([key]) => key.toLowerCase() === name,
	);
	if (matches.length > 1 || (matches[0] && typeof matches[0][1] !== "string")) {
		throw new DAPError("InvalidResponse", "Ambiguous response header");
	}
	return matches[0]?.[1];
}

export function checkMediaType(
	headers: Readonly<Record<string, string>>,
	message: string,
	version: 18 | 19 = 19,
): void {
	const [type, ...parts] = (header(headers, "content-type") ?? "").split(";");
	const parameters = new Map<string, string>();
	for (const part of parts) {
		const match = /^\s*([\w-]+)\s*=\s*(?:"([^"\\]*)"|([^\s";]+))\s*$/.exec(
			part,
		);
		if (!match || parameters.has(match[1]!.toLowerCase()))
			throw new DAPError("InvalidResponse", "Invalid media type parameters");
		parameters.set(match[1]!.toLowerCase(), match[2] ?? match[3]!);
	}
	if (
		type?.trim().toLowerCase() !== "application/ppm-dap" ||
		parameters.get("message") !== message ||
		(parameters.has("version") && parameters.get("version") !== String(version))
	) {
		throw new DAPError("InvalidResponse", "Unexpected DAP media type");
	}
}

export function checkStatus(response: DAPResponse): void {
	if (
		!Number.isInteger(response.status) ||
		response.status < 100 ||
		response.status > 599
	) {
		throw new DAPError("InvalidResponse", "Invalid HTTP status");
	}
	if (response.status < 200 || response.status >= 300) {
		throw new DAPError(
			"HttpError",
			`DAP request failed with HTTP ${response.status}`,
		);
	}
}

const rejectionCodes: readonly ReportRejection["code"][] = [
	"unknown",
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

function processUpload(
	response: DAPResponse,
	ids: readonly ReportId[],
): UploadResult {
	checkStatus(response);
	bytes(response.body);
	const rejected: ReportRejection[] = [];
	if (response.body.length) {
		checkMediaType(response.headers, "upload-errors");
		if (response.body.length > ids.length * 17)
			throw new DAPError("InvalidResponse", "Too many upload errors");
		const positions = new Map(ids.map((id, i) => [id as string, i]));
		let previous = -1;
		try {
			for (const error of decodeUploadErrors(response.body)) {
				const index = positions.get(error.id);
				if (index === undefined || index <= previous)
					throw new DAPError(
						"InvalidResponse",
						"Unknown, duplicate, or unordered report ID",
					);
				previous = index;
				rejected.push(
					Object.freeze({
						id: ids[index]!,
						rawCode: error.rawCode,
						code: rejectionCodes[error.rawCode] ?? "unknown",
					}),
				);
			}
		} catch (cause) {
			if (cause instanceof DAPError && cause.code === "InvalidResponse")
				throw cause;
			throw new DAPError("InvalidResponse", "Malformed upload errors", {
				cause,
			});
		}
	}
	const failed = new Set(rejected.map((error) => error.id));
	return Object.freeze({
		accepted: Object.freeze(ids.filter((id) => !failed.has(id))),
		rejected: Object.freeze(rejected),
		ok: rejected.length === 0,
	});
}

export class Client<M> {
	readonly task: Task<M>;
	#hpke: AggregatorHpkeConfigs;
	#configs: readonly [HpkeConfig, HpkeConfig];
	#suite: ReturnType<typeof createSuite>;
	#keys: Promise<CryptoKey[]> | undefined;
	#random: RandomSource;
	#customRandom: RandomSource | undefined;
	#clock: () => number;
	#binding: string;

	constructor(task: Task<M>, options: ClientOptions) {
		if (!(task instanceof Task))
			throw new DAPError("InvalidTask", "Expected a Task");
		this.task = task;
		this.#hpke = Object.freeze({
			leader: options.hpke.leader,
			helper: options.hpke.helper,
		});
		this.#configs = [
			selectConfig(this.#hpke.leader),
			selectConfig(this.#hpke.helper),
		];
		this.#customRandom = options.random;
		this.#random = options.random ?? secureRandom;
		this.#clock = options.clock ?? Date.now;
		this.#suite = createSuite(options.random);
		this.#binding = `${task.id}:${base64url(task.encodeConfiguration())}`;
		Object.freeze(this);
	}

	withHpkeConfigs(hpke: AggregatorHpkeConfigs): Client<M> {
		return new Client(this.task, {
			hpke,
			clock: this.#clock,
			...(this.#customRandom ? { random: this.#customRandom } : {}),
		});
	}

	async prepareReport(
		measurement: M,
		options: PrepareReportOptions = {},
	): Promise<PreparedReport> {
		if (
			this.task.vdaf.type === "prio3-count" &&
			measurement !== 0 &&
			measurement !== 1
		)
			throw new DAPError(
				"InvalidMeasurement",
				"Count measurement must be 0 or 1",
			);
		if (this.task.vdaf.type === "prio3-sum") {
			try {
				validateSumMeasurement(
					measurement as number | bigint,
					this.task.vdaf.maxMeasurement!,
				);
			} catch (cause) {
				throw new DAPError(
					"InvalidMeasurement",
					"Sum measurement is outside its bound",
					{ cause },
				);
			}
		}
		if (this.task.vdaf.type === "prio3-histogram") {
			try {
				validateHistogramMeasurement(
					measurement as number,
					this.task.vdaf.length!,
				);
			} catch (cause) {
				throw new DAPError(
					"InvalidMeasurement",
					"Histogram bucket is outside its range",
					{ cause },
				);
			}
		}
		const milliseconds =
			options.time instanceof Date
				? options.time.getTime()
				: (options.time ?? this.#clock());
		if (!Number.isSafeInteger(milliseconds) || milliseconds < 0)
			throw new DAPError(
				"InvalidReport",
				"Expected non-negative Unix milliseconds",
			);
		const time = Number(
			BigInt(milliseconds) / (1000n * BigInt(this.task.timePrecision)),
		);
		this.task.validateTime(time);
		const copyExtensions = (extensions: readonly Extension[]) =>
			extensions.map((extension) => ({
				type: extension.type,
				data: bytes(extension.data).slice(),
			}));
		const publicExtensions = copyExtensions(options.publicExtensions ?? []);
		const privateExtensions = [
			copyExtensions(options.privateExtensions?.leader ?? []),
			copyExtensions(options.privateExtensions?.helper ?? []),
		];
		for (const extensions of privateExtensions) {
			const types = [...publicExtensions, ...extensions].map(
				(extension) => extension.type,
			);
			if (new Set(types).size !== types.length)
				throw new DAPError(
					"InvalidReport",
					"Duplicate public/private extension type",
				);
		}
		const nonce = randomBytes(this.#random, 16);
		const rand = randomBytes(
			this.#random,
			this.task.vdaf.type === "prio3-histogram" ? 128 : 64,
		);
		const taskId = decodeId(this.task.id, 32);
		const dapVersion = `dap-${this.task.dapVersion}`;
		const ctx = concat(new TextEncoder().encode(dapVersion), taskId);
		let shares: ReturnType<typeof shardCountWithRandomness>;
		try {
			try {
				shares =
					this.task.vdaf.type === "prio3-count"
						? shardCountWithRandomness(measurement as number, ctx, nonce, rand)
						: this.task.vdaf.type === "prio3-sum"
							? shardSumWithRandomness(
									measurement as number | bigint,
									this.task.vdaf.maxMeasurement!,
									ctx,
									nonce,
									rand,
								)
							: shardHistogramWithRandomness(
									measurement as number,
									this.task.vdaf.length!,
									this.task.vdaf.chunkLength!,
									ctx,
									nonce,
									rand,
								);
			} catch (cause) {
				if (cause instanceof RangeError || cause instanceof TypeError)
					throw new DAPError("InvalidMeasurement", cause.message, { cause });
				throw cause;
			}
		} finally {
			rand.fill(0);
		}
		const metadata = { id: nonce, time: BigInt(time), publicExtensions };
		const aad = encodeInputShareAad(
			taskId,
			this.task.encodeConfiguration(),
			metadata,
			shares.publicShare,
		);
		// Snapshot caller-owned extensions before the first asynchronous operation.
		const plaintexts = shares.inputShares.map((share, i) =>
			encodePlaintextInputShare(share, privateExtensions[i]),
		);
		try {
			this.#keys ??= Promise.all(
				this.#configs.map((config) =>
					this.#suite.DeserializePublicKey(config.publicKey),
				),
			);
			const keys = await this.#keys;
			const results = await Promise.allSettled(
				plaintexts.map(async (plaintext, i) => {
					const info = concat(
						new TextEncoder().encode(`${dapVersion} input share`),
						Uint8Array.of(1, i + 2),
					);
					const sealed = await this.#suite.Seal(keys[i]!, plaintext, {
						info,
						aad,
					});
					return {
						configId: this.#configs[i]!.id,
						enc: sealed.encapsulatedSecret,
						payload: sealed.ciphertext,
					};
				}),
			);
			const ciphertexts = results.map((result) => {
				if (result.status === "rejected") throw result.reason;
				return result.value;
			});
			return preparedReport(
				base64url(nonce) as ReportId,
				time,
				this.#binding,
				encodeReport({
					metadata,
					publicShare: shares.publicShare,
					leader: ciphertexts[0]!,
					helper: ciphertexts[1]!,
				}),
			);
		} catch (cause) {
			throw new DAPError(
				"EncryptionFailed",
				"Could not encrypt report shares",
				{ cause },
			);
		} finally {
			for (const plaintext of plaintexts) plaintext.fill(0);
			for (const share of shares.inputShares) share.fill(0);
		}
	}

	async prepareReports(
		measurements: readonly M[],
		options: PrepareReportOptions & { readonly concurrency?: number } = {},
	): Promise<readonly PreparedReport[]> {
		const concurrency = options.concurrency ?? 4;
		if (!Number.isSafeInteger(concurrency) || concurrency < 1)
			throw new DAPError(
				"InvalidReport",
				"Concurrency must be a positive integer",
			);
		const inputs = Array.from(measurements);
		const reports = new Array<PreparedReport>(inputs.length);
		let next = 0;
		let failed = false;
		await Promise.all(
			Array.from({ length: Math.min(concurrency, inputs.length) }, async () => {
				while (!failed && next < inputs.length) {
					const index = next++;
					try {
						reports[index] = await this.prepareReport(inputs[index]!, options);
					} catch (cause) {
						failed = true;
						throw cause;
					}
				}
			}),
		);
		return Object.freeze(reports);
	}

	prepareUpload(reports: readonly PreparedReport[]): PreparedUpload {
		if (!reports.length)
			throw new DAPError("InvalidReport", "Expected at least one report");
		const encoded = reports.map((report) => reportBytes(report, this.#binding));
		const ids = reports.map((report) => report.id);
		if (new Set(ids).size !== ids.length)
			throw new DAPError("InvalidReport", "Duplicate report IDs in upload");
		const body = concatParts(encoded);
		const url = resource(this.task.leader, `tasks/${this.task.id}/reports`);
		const headers = Object.freeze({
			"content-type": "application/ppm-dap;message=upload-req",
		});
		return Object.freeze({
			get request(): DAPRequest {
				return Object.freeze({
					url,
					method: "POST" as const,
					headers,
					body: body.slice(),
				});
			},
			process: (response: DAPResponse) => processUpload(response, ids),
		});
	}
}
