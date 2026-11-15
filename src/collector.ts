import { bytes, concat, decodeId } from "./binary.js";
import {
	checkResponseType,
	checkStatus,
	dapRequest,
	readBody,
	resource,
} from "./client.js";
import { DAPError } from "./errors.js";
import { createSuite, prepareRecipientKey } from "./hpke.js";
import {
	type CollectionJobResponse,
	decodeCollectionJobResponse,
	encodeCollectionJobRequest,
} from "./messages.js";
import { DAP_VERSION, Task, toMs, toTime } from "./task.js";
import { type AggregateResult, unshard, type Vdaf } from "./vdaf.js";

/**
 * A time-interval task queries an interval whose ends fall on the task's time
 * precision. A leader-selected task asks for the next batch under an
 * idempotency key: 1 to 255 bytes in URL-safe Base 64, unique in the task.
 * Save the key before sending so a retry cannot claim a second batch.
 */
export type CollectionQuery =
	| {
			/** Date or Unix milliseconds, inclusive. */
			readonly start: Date | number;
			/** Date or Unix milliseconds, exclusive. */
			readonly end: Date | number;
	  }
	| { readonly idempotencyKey: string };

/** Persist this JSON-safe object to resume an asynchronous collection job. */
export type CollectionState = { readonly location: string } & (
	| {
			/** Unix milliseconds. */
			readonly start: number;
			readonly end: number;
	  }
	| { readonly idempotencyKey: string }
);

type Query = { start: number; end: number } | { idempotencyKey: string };

export type CollectionProgress<V extends Vdaf = Vdaf> =
	| {
			readonly status: "pending";
			readonly state: CollectionState;
			/** Seconds the Leader asked the Collector to wait, if it said. */
			readonly retryAfter: number | undefined;
	  }
	| {
			readonly status: "complete";
			readonly value: AggregateResult<V>;
			readonly reportCount: number;
			/** The smallest interval holding every report, in Unix milliseconds. */
			readonly interval: { readonly start: number; readonly end: number };
	  };

export interface PreparedCollection<V extends Vdaf = Vdaf> {
	/** A fresh Request on each read. Add authentication before sending it. */
	readonly request: Request;
	process(response: Response): Promise<CollectionProgress<V>>;
}

export interface CollectorOptions {
	/** ID of the collector HPKE configuration provisioned on both aggregators. */
	readonly configId: number;
	/** Raw X25519 private key bytes. Keep them on the backend. */
	readonly privateKey: Uint8Array;
	/** Unix milliseconds, as returned by Date.now(). Used for Retry-After dates. */
	readonly clock?: () => number;
}

/** Decode an idempotency key of 1 to 255 bytes (DAP 20, 5.2.1). */
function idempotencyKey(key: string): Uint8Array {
	const length = Math.floor(((key?.length ?? 0) * 3) / 4);
	if (length < 1 || length > 255)
		throw new DAPError("InvalidMessage", "Invalid idempotency key");
	return decodeId(key, length);
}

// A collection response holds two ciphertexts of at most one Field128 share
// per histogram bucket plus fixed framing.
const MAX_RESPONSE = 2 * (4096 * 16 + 16 + 64) + 64;

export class Collector<V extends Vdaf = Vdaf> {
	readonly task: Task<V>;
	#configId: number;
	#suite = createSuite();
	#key: CryptoKeyPair;
	#clock: () => number;
	#creationUrl: string;

	private constructor(
		task: Task<V>,
		options: CollectorOptions,
		key: CryptoKeyPair,
	) {
		if (!key)
			throw new DAPError(
				"InvalidTask",
				"Use Collector.create() to build a Collector",
			);
		this.#key = key;
		this.task = task;
		this.#configId = options.configId;
		this.#clock = options.clock ?? Date.now;
		this.#creationUrl = resource(
			task.leader,
			`tasks/${task.id}/collection_jobs`,
		);
		Object.freeze(this);
	}

	/** Import the collector private key and bind the collection job URL. */
	static async create<V extends Vdaf>(
		task: Task<V>,
		options: CollectorOptions,
	): Promise<Collector<V>> {
		if (!(task instanceof Task) || task.dapVersion !== DAP_VERSION)
			throw new DAPError(
				"InvalidTask",
				`Collector requires a DAP ${DAP_VERSION} task`,
			);
		if (
			!Number.isInteger(options.configId) ||
			options.configId < 0 ||
			options.configId > 255
		)
			throw new DAPError(
				"InvalidHpkeConfig",
				"Invalid collector HPKE config ID",
			);
		const { pair } = await prepareRecipientKey(bytes(options.privateKey, 32));
		return new Collector(task, options, pair);
	}

	prepare(query: CollectionQuery): PreparedCollection<V> {
		const checked = this.#query(query);
		const body = this.#request(checked);
		const url = this.#creationUrl;
		return {
			get request() {
				return dapRequest(
					url,
					"POST",
					{ "content-type": "application/ppm-dap;message=collection-job-req" },
					body,
				);
			},
			process: (response) => this.#process(response, body, checked),
		};
	}

	resume(state: CollectionState): PreparedCollection<V> {
		if (!state || typeof state !== "object")
			throw new DAPError("InvalidMessage", "Invalid saved collection state");
		const checked = this.#query(state);
		const body = this.#request(checked);
		const location = this.#location(state.location);
		return {
			get request() {
				return dapRequest(location, "GET", {
					accept: "application/ppm-dap;message=collection-job-resp",
				});
			},
			process: (response) => this.#process(response, body, checked, location),
		};
	}

	#query(query: CollectionQuery): Query {
		const leaderSelected = this.task.batchMode === "leader-selected";
		if (leaderSelected !== "idempotencyKey" in query)
			throw new DAPError(
				"InvalidMessage",
				leaderSelected
					? "Leader-selected collections need an idempotency key"
					: "Time-interval collections need start and end",
			);
		if ("idempotencyKey" in query) {
			idempotencyKey(query.idempotencyKey);
			return { idempotencyKey: query.idempotencyKey };
		}
		const ms = (value: Date | number) =>
			value instanceof Date ? value.getTime() : value;
		const interval = { start: ms(query.start), end: ms(query.end) };
		const unit = this.task.timePrecision * 1000;
		for (const value of [interval.start, interval.end])
			if (!Number.isSafeInteger(value) || value < 0 || value % unit)
				throw new DAPError(
					"InvalidMessage",
					`Collection bounds must be multiples of ${unit} ms`,
				);
		if (interval.end <= interval.start)
			throw new DAPError("InvalidMessage", "Collection interval is empty");
		return interval;
	}

	#request(query: Query): Uint8Array<ArrayBuffer> {
		if ("idempotencyKey" in query)
			return encodeCollectionJobRequest(idempotencyKey(query.idempotencyKey));
		const start = toTime(this.task, query.start);
		return encodeCollectionJobRequest(
			start,
			toTime(this.task, query.end) - start,
		);
	}

	#location(value: string | null): string {
		if (typeof value !== "string" || !value || value.length > 2048)
			throw new DAPError("InvalidResponse", "Invalid collection job location");
		let url: URL;
		try {
			url = new URL(value, this.#creationUrl);
		} catch {
			throw new DAPError("InvalidResponse", "Invalid collection job location");
		}
		// DAP 20, 3.2 lets the Leader choose the job identifier and its shape,
		// so only require that the job stays on the Leader's origin and carries
		// no credentials or fragment.
		if (
			url.origin !== new URL(this.#creationUrl).origin ||
			url.username ||
			url.password ||
			url.hash
		)
			throw new DAPError(
				"InvalidResponse",
				"Collection job location is outside the task",
			);
		return url.href;
	}

	async #process(
		response: Response,
		requestBody: Uint8Array,
		query: Query,
		previousLocation?: string,
	): Promise<CollectionProgress<V>> {
		await checkStatus(response);
		const body = await readBody(response, MAX_RESPONSE);
		const location =
			previousLocation ?? this.#location(response.headers.get("location"));
		if (!body.length) {
			const value = response.headers.get("retry-after");
			let retryAfter: number | undefined;
			if (value !== null) {
				if (/^[0-9]+$/.test(value)) retryAfter = Number(value);
				else {
					const date = Date.parse(value);
					if (!Number.isNaN(date))
						retryAfter = Math.max(0, Math.ceil((date - this.#clock()) / 1000));
				}
				if (retryAfter === undefined || !Number.isSafeInteger(retryAfter))
					throw new DAPError("InvalidResponse", "Invalid Retry-After header");
			}
			return {
				status: "pending",
				state: { location, ...query },
				retryAfter,
			};
		}
		checkResponseType(response, "collection-job-resp", this.task.dapVersion);
		let result: CollectionJobResponse;
		try {
			result = decodeCollectionJobResponse(body);
		} catch (cause) {
			throw new DAPError("InvalidResponse", "Malformed collection response", {
				cause,
			});
		}
		if (
			("start" in query &&
				(result.start < toTime(this.task, query.start) ||
					result.start + result.duration > toTime(this.task, query.end))) ||
			result.reportCount < BigInt(this.task.minBatchSize) ||
			result.reportCount > BigInt(Number.MAX_SAFE_INTEGER)
		)
			throw new DAPError(
				"InvalidResponse",
				"Collection batch does not match the query",
			);
		const aad = concat(
			decodeId(this.task.id, 32),
			this.task.encodeConfiguration(),
			requestBody,
		);
		const shares: Uint8Array[] = [];
		for (const [index, ciphertext] of [
			result.leader,
			result.helper,
		].entries()) {
			if (
				ciphertext.configId !== this.#configId ||
				ciphertext.enc.length !== 32
			)
				throw new DAPError(
					"InvalidResponse",
					"Unexpected collector HPKE configuration",
				);
			const info = concat(
				new TextEncoder().encode(`dap-${DAP_VERSION} aggregate share`),
				Uint8Array.of(index + 2, 0),
			);
			try {
				shares.push(
					await this.#suite.Open(
						this.#key,
						ciphertext.enc,
						ciphertext.payload,
						{
							info,
							aad,
						},
					),
				);
			} catch (cause) {
				throw new DAPError(
					"DecryptionFailed",
					"Could not decrypt aggregate share",
					{ cause },
				);
			}
		}
		let value: bigint | bigint[];
		try {
			value = unshard(
				this.task.vdaf,
				shares as [Uint8Array, Uint8Array],
				result.reportCount,
			);
		} catch (cause) {
			throw new DAPError("InvalidResponse", "Invalid aggregate share", {
				cause,
			});
		}
		return {
			status: "complete",
			value: (Array.isArray(value)
				? Object.freeze(value)
				: value) as AggregateResult<V>,
			reportCount: Number(result.reportCount),
			interval: {
				start: toMs(this.task, result.start),
				end: toMs(this.task, result.start + result.duration),
			},
		};
	}
}
