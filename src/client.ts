import { base64url, bytes, concat, concatParts, decodeId } from "./binary.js";
import { DAPError, type DAPProblem } from "./errors.js";
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
import {
	type PreparedReport,
	preparedReport,
	type ReportError,
	type ReportId,
	reportBytes,
	reportErrors,
} from "./reports.js";
import { Task, toMs, toTime } from "./task.js";
import {
	type Measurement,
	randomLength,
	shard,
	type Vdaf,
	validateMeasurement,
} from "./vdaf.js";

export interface ReportRejection {
	readonly id: ReportId;
	/** "unknown" for a codepoint this package does not know; see `rawCode`. */
	readonly error: ReportError | "unknown";
	readonly rawCode: number;
}
export interface UploadResult {
	readonly accepted: readonly ReportId[];
	readonly rejected: readonly ReportRejection[];
	readonly ok: boolean;
}
export interface PreparedUpload {
	/** A fresh Request on each read, so a retry can send it again. */
	readonly request: Request;
	process(response: Response): Promise<UploadResult>;
}
export interface ClientOptions {
	readonly hpke: AggregatorHpkeConfigs;
	readonly random?: RandomSource;
	/** Unix milliseconds, as returned by Date.now(). */
	readonly clock?: () => number;
}
export interface PrepareReportOptions {
	/** Date or Unix milliseconds. Defaults to the client clock. */
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

/**
 * Build a DAP request that never follows redirects or sends cookies. A
 * redirect arrives as a non-2xx response and fails the status check;
 * workerd rejects redirect "error".
 */
export function dapRequest(
	url: string,
	method: "GET" | "POST",
	headers: Record<string, string>,
	body?: Uint8Array,
): Request {
	return new Request(url, {
		method,
		headers,
		redirect: "manual",
		credentials: "omit",
		...(body ? { body: body.slice() } : {}),
	});
}

/** Read a response body, refusing more than limit bytes. */
export async function readBody(
	response: Response,
	limit: number,
): Promise<Uint8Array> {
	const chunks: Uint8Array[] = [];
	let size = 0;
	const reader = response.body?.getReader();
	if (!reader) return new Uint8Array();
	try {
		while (true) {
			const next = await reader.read();
			if (next.done) break;
			size += next.value.length;
			if (size > limit) {
				await reader.cancel();
				throw new DAPError(
					"InvalidResponse",
					"Response exceeds the size limit",
				);
			}
			chunks.push(next.value);
		}
	} finally {
		reader.releaseLock();
	}
	return concatParts(chunks);
}

/** Check a DAP media type, accepting parameters in any order and case. */
export function checkMediaType(
	contentType: string | null | undefined,
	message: string,
	version: 18 | 19 = 19,
): void {
	const [type, ...parts] = (contentType ?? "").split(";");
	const parameters = new Map<string, string>();
	for (const part of parts) {
		const match = /^\s*([\w-]+)\s*=\s*(?:"([^"\\]*)"|([^\s";]+))\s*$/.exec(
			part,
		);
		if (!match || parameters.has(match[1]!.toLowerCase()))
			throw new DAPError("InvalidMessage", "Invalid media type parameters");
		parameters.set(match[1]!.toLowerCase(), match[2] ?? match[3]!);
	}
	if (
		type?.trim().toLowerCase() !== "application/ppm-dap" ||
		parameters.get("message") !== message ||
		(parameters.has("version") && parameters.get("version") !== String(version))
	) {
		throw new DAPError("InvalidMessage", "Unexpected DAP media type");
	}
}

/** Check a response's media type, reporting a mismatch as the peer's fault. */
export function checkResponseType(
	response: Response,
	message: string,
	version: 18 | 19 = 19,
): void {
	try {
		checkMediaType(response.headers.get("content-type"), message, version);
	} catch (cause) {
		throw new DAPError("InvalidResponse", "Unexpected DAP media type", {
			cause,
		});
	}
}

const DAP_ERROR_URN = "urn:ietf:params:ppm:dap:error:";

/** Read an RFC 9457 problem detail document from an error body (DAP 19, 3.6). */
function parseProblem(
	contentType: string,
	body: Uint8Array,
): DAPProblem | undefined {
	if (!/^application\/problem\+json\s*(?:;|$)/i.test(contentType.trim()))
		return undefined;
	let document: unknown;
	try {
		document = JSON.parse(
			new TextDecoder("utf-8", { fatal: true }).decode(body),
		);
	} catch {
		return undefined;
	}
	if (!document || typeof document !== "object" || Array.isArray(document))
		return undefined;
	const fields = document as Record<string, unknown>;
	const uri = typeof fields.type === "string" ? fields.type : "about:blank";
	const text = (name: string) =>
		typeof fields[name] === "string" ? { [name]: fields[name] } : {};
	return Object.freeze({
		type: uri,
		...(uri.startsWith(DAP_ERROR_URN)
			? { dapError: uri.slice(DAP_ERROR_URN.length) }
			: {}),
		...text("title"),
		...text("detail"),
		...(typeof fields.taskid === "string" ? { taskId: fields.taskid } : {}),
	}) as DAPProblem;
}

/** Throw DAPError for a non-2xx response, carrying its problem document. */
export async function checkStatus(response: Response): Promise<void> {
	if (response.status >= 200 && response.status < 300) return;
	let problem: DAPProblem | undefined;
	try {
		// A problem document is small; refuse to buffer an oversized body.
		problem = parseProblem(
			response.headers.get("content-type") ?? "",
			await readBody(response, 65536),
		);
	} catch {}
	const reason = problem?.dapError ?? problem?.title;
	throw new DAPError(
		"HttpError",
		`DAP request failed with HTTP ${response.status}${reason ? `: ${reason}` : ""}`,
		problem ? { problem } : undefined,
	);
}

async function processUpload(
	response: Response,
	ids: readonly ReportId[],
): Promise<UploadResult> {
	await checkStatus(response);
	const body = await readBody(response, ids.length * 17);
	const rejected: ReportRejection[] = [];
	if (body.length) {
		checkResponseType(response, "upload-errors");
		const positions = new Map(ids.map((id, i) => [id as string, i]));
		let previous = -1;
		try {
			for (const error of decodeUploadErrors(body)) {
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
						error: reportErrors[error.rawCode] ?? "unknown",
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

export class Client<V extends Vdaf = Vdaf> {
	readonly task: Task<V>;
	#hpke: AggregatorHpkeConfigs;
	#configs: readonly [HpkeConfig, HpkeConfig];
	#suite: ReturnType<typeof createSuite>;
	#keys: readonly CryptoKey[];
	#random: RandomSource;
	#customRandom: RandomSource | undefined;
	#clock: () => number;
	#binding: string;

	private constructor(
		task: Task<V>,
		options: ClientOptions,
		keys: readonly CryptoKey[],
	) {
		if (!keys)
			throw new DAPError(
				"InvalidTask",
				"Use Client.create() to build a Client",
			);
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
		this.#keys = keys;
		Object.freeze(this);
	}

	/** Select each Aggregator's HPKE configuration and import its public key. */
	static async create<V extends Vdaf>(
		task: Task<V>,
		options: ClientOptions,
	): Promise<Client<V>> {
		if (!(task instanceof Task))
			throw new DAPError("InvalidTask", "Expected a Task");
		const suite = createSuite(options.random);
		let keys: CryptoKey[];
		try {
			keys = await Promise.all(
				[options.hpke?.leader, options.hpke?.helper].map((list) =>
					suite.DeserializePublicKey(selectConfig(list!).publicKey),
				),
			);
		} catch (cause) {
			if (cause instanceof DAPError) throw cause;
			throw new DAPError("InvalidHpkeConfig", "Unusable HPKE public key", {
				cause,
			});
		}
		return new Client(task, options, keys);
	}

	/** Rebuild this client against freshly retrieved HPKE configurations. */
	withHpkeConfigs(hpke: AggregatorHpkeConfigs): Promise<Client<V>> {
		return Client.create(this.task, {
			hpke,
			clock: this.#clock,
			...(this.#customRandom ? { random: this.#customRandom } : {}),
		});
	}

	async prepareReport(
		measurement: Measurement<V>,
		options: PrepareReportOptions = {},
	): Promise<PreparedReport> {
		try {
			validateMeasurement(this.task.vdaf, measurement);
		} catch (cause) {
			throw new DAPError(
				"InvalidMeasurement",
				cause instanceof Error ? cause.message : "Invalid measurement",
				{ cause },
			);
		}
		const milliseconds =
			options.time instanceof Date
				? options.time.getTime()
				: (options.time ?? this.#clock());
		const time = toTime(this.task, milliseconds);
		if (!this.task.inInterval(time))
			throw new DAPError(
				"InvalidReport",
				"Report time is outside the task interval",
			);
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
		const rand = randomBytes(this.#random, randomLength(this.task.vdaf));
		const taskId = decodeId(this.task.id, 32);
		const dapVersion = `dap-${this.task.dapVersion}`;
		const ctx = concat(new TextEncoder().encode(dapVersion), taskId);
		let shares: ReturnType<typeof shard>;
		try {
			shares = shard(this.task.vdaf, measurement, ctx, nonce, rand);
		} catch (cause) {
			if (cause instanceof RangeError || cause instanceof TypeError)
				throw new DAPError("InvalidMeasurement", cause.message, { cause });
			throw cause;
		} finally {
			rand.fill(0);
		}
		const metadata = { id: nonce, time, publicExtensions };
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
			const keys = this.#keys;
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
				toMs(this.task, time),
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
		measurements: readonly Measurement<V>[],
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
		return Object.freeze({
			get request(): Request {
				return dapRequest(
					url,
					"POST",
					{ "content-type": "application/ppm-dap;message=upload-req" },
					body,
				);
			},
			process: (response: Response) => processUpload(response, ids),
		});
	}
}
