import { bytes, concat, decodeId } from "./binary.js";
import {
	checkMediaType,
	checkStatus,
	type DAPRequest,
	type DAPResponse,
	header,
	resource,
} from "./client.js";
import { DAPError } from "./errors.js";
import { createSuite } from "./hpke.js";
import {
	type CollectionJobResponse,
	decodeCollectionJobResponse,
	encodeCollectionJobRequest,
} from "./messages.js";
import { unshardCount } from "./prio3-count.js";
import { Task } from "./task.js";

export interface CollectionQuery {
	/** DAP time-precision units, not Unix seconds. */
	readonly start: number | bigint;
	readonly duration: number | bigint;
}

/** Persist this object to resume an asynchronous collection job. */
export interface CollectionState {
	readonly location: string;
	readonly start: string;
	readonly duration: string;
}

export type CollectionProgress =
	| {
			readonly status: "pending";
			readonly state: CollectionState;
			readonly retryAfter: number | undefined;
	  }
	| {
			readonly status: "complete";
			readonly count: bigint;
			readonly reportCount: bigint;
			readonly interval: { readonly start: bigint; readonly duration: bigint };
	  };

export interface PreparedCollection {
	readonly request: DAPRequest;
	process(response: DAPResponse): Promise<CollectionProgress>;
}

export interface CollectorOptions {
	/** ID of the collector HPKE configuration provisioned on both aggregators. */
	readonly configId: number;
	/** Raw X25519 private key bytes. Keep them on the backend. */
	readonly privateKey: Uint8Array;
}

export class Collector {
	readonly task: Task<number>;
	#configId: number;
	#suite = createSuite();
	#key: Promise<CryptoKey>;
	#creationUrl: string;

	constructor(task: Task<number>, options: CollectorOptions) {
		if (!(task instanceof Task) || task.dapVersion !== 19)
			throw new DAPError("InvalidTask", "Collector requires a DAP 19 task");
		if (
			!Number.isInteger(options.configId) ||
			options.configId < 0 ||
			options.configId > 255
		)
			throw new DAPError(
				"InvalidHpkeConfig",
				"Invalid collector HPKE config ID",
			);
		const secret = bytes(options.privateKey, 32).slice();
		this.#key = this.#suite
			.DeserializePrivateKey(secret)
			.finally(() => secret.fill(0));
		this.task = task;
		this.#configId = options.configId;
		this.#creationUrl = resource(
			task.leader,
			`tasks/${task.id}/collection_jobs`,
		);
		Object.freeze(this);
	}

	prepare(query: CollectionQuery): PreparedCollection {
		const body = encodeCollectionJobRequest(query.start, query.duration);
		const start = BigInt(query.start).toString();
		const duration = BigInt(query.duration).toString();
		return {
			request: {
				method: "POST",
				url: this.#creationUrl,
				headers: {
					"content-type": "application/ppm-dap;message=collection-job-req",
				},
				body: body.slice(),
			},
			process: (response) => this.#process(response, body, start, duration),
		};
	}

	resume(state: CollectionState): PreparedCollection {
		if (
			!state ||
			typeof state !== "object" ||
			typeof state.start !== "string" ||
			typeof state.duration !== "string" ||
			state.start.length > 20 ||
			state.duration.length > 20 ||
			!/^(0|[1-9][0-9]*)$/.test(state.start) ||
			!/^[1-9][0-9]*$/.test(state.duration)
		)
			throw new DAPError("InvalidMessage", "Invalid saved collection interval");
		const body = encodeCollectionJobRequest(
			BigInt(state.start),
			BigInt(state.duration),
		);
		const location = this.#location(state.location);
		return {
			request: {
				method: "GET",
				url: location,
				headers: { accept: "application/ppm-dap;message=collection-job-resp" },
			},
			process: (response) =>
				this.#process(response, body, state.start, state.duration, location),
		};
	}

	#location(value: string): string {
		if (typeof value !== "string")
			throw new DAPError("InvalidResponse", "Invalid collection job location");
		let url: URL;
		try {
			url = new URL(value, this.#creationUrl);
		} catch {
			throw new DAPError("InvalidResponse", "Invalid collection job location");
		}
		const base = new URL(this.#creationUrl);
		const prefix = `${base.pathname}/`;
		const id = url.pathname.startsWith(prefix)
			? url.pathname.slice(prefix.length)
			: "";
		if (
			url.origin !== base.origin ||
			url.username ||
			url.password ||
			url.search ||
			url.hash ||
			!/^[A-Za-z0-9_-]{22}$/.test(id)
		)
			throw new DAPError(
				"InvalidResponse",
				"Collection job location is outside the task",
			);
		decodeId(id, 16);
		return url.href;
	}

	async #process(
		response: DAPResponse,
		requestBody: Uint8Array,
		start: string,
		duration: string,
		previousLocation?: string,
	): Promise<CollectionProgress> {
		checkStatus(response);
		bytes(response.body);
		const location =
			previousLocation ??
			this.#location(header(response.headers, "location") ?? "");
		if (!response.body.length) {
			const value = header(response.headers, "retry-after");
			let retryAfter: number | undefined;
			if (value !== undefined) {
				if (/^[0-9]+$/.test(value)) retryAfter = Number(value);
				else {
					const date = Date.parse(value);
					if (!Number.isNaN(date))
						retryAfter = Math.max(0, Math.ceil((date - Date.now()) / 1000));
				}
				if (retryAfter === undefined || !Number.isSafeInteger(retryAfter))
					throw new DAPError("InvalidResponse", "Invalid Retry-After header");
			}
			return {
				status: "pending",
				state: { location, start, duration },
				retryAfter,
			};
		}
		checkMediaType(
			response.headers,
			"collection-job-resp",
			this.task.dapVersion,
		);
		let result: CollectionJobResponse;
		try {
			result = decodeCollectionJobResponse(response.body);
		} catch (cause) {
			throw new DAPError("InvalidResponse", "Malformed collection response", {
				cause,
			});
		}
		const queryStart = BigInt(start);
		const queryEnd = queryStart + BigInt(duration);
		if (
			result.start < queryStart ||
			result.start + result.duration > queryEnd ||
			result.reportCount < BigInt(this.task.minBatchSize) ||
			result.reportCount >= 0xffff_ffff_0000_0001n
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
		const key = await this.#key;
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
				new TextEncoder().encode("dap-19 aggregate share"),
				Uint8Array.of(index + 2, 0),
			);
			try {
				shares.push(
					await this.#suite.Open(key, ciphertext.enc, ciphertext.payload, {
						info,
						aad,
					}),
				);
			} catch (cause) {
				throw new DAPError(
					"DecryptionFailed",
					"Could not decrypt aggregate share",
					{ cause },
				);
			}
		}
		let count: bigint;
		try {
			count = unshardCount(shares as [Uint8Array, Uint8Array]);
		} catch (cause) {
			throw new DAPError("InvalidResponse", "Malformed count aggregate share", {
				cause,
			});
		}
		if (count > result.reportCount)
			throw new DAPError("InvalidResponse", "Count exceeds the report count");
		return {
			status: "complete",
			count,
			reportCount: result.reportCount,
			interval: { start: result.start, duration: result.duration },
		};
	}
}
