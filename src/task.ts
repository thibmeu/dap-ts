import { base64url, bytes, concat, decodeId, Reader, uint } from "./binary.js";
import { DAPError } from "./errors.js";
import {
	type DecodeOptions,
	decodeTaskConfiguration,
	type Extension,
	encodeTaskConfiguration,
	type TaskConfiguration,
} from "./messages.js";
import { type ClientVdaf, prio3Count } from "./prio3-count.js";
import { prio3Histogram } from "./prio3-histogram.js";
import { prio3Sum } from "./prio3-sum.js";

export interface TaskOptions<M> {
	readonly id: string;
	readonly info?: string | Uint8Array;
	readonly leader: string;
	readonly helper: string;
	/** Seconds per DAP time unit. */
	readonly timePrecision: number;
	readonly minBatchSize: number;
	readonly batchMode: "time-interval";
	readonly vdaf: ClientVdaf<M>;
	readonly extensions?: readonly Extension[];
	/** Test-only compatibility with Janus's unreleased DAP 18 profile. */
	readonly testOnly?: {
		readonly dapVersion: 18;
		readonly allowInsecureHttp: true;
	};
}
export interface EncodedTask {
	readonly id: string;
	readonly configuration: Uint8Array;
}

function endpoint(value: Uint8Array, allowInsecureHttp = false): string {
	if (!value.length || value.some((byte) => byte < 0x21 || byte > 0x7e)) {
		throw new DAPError("InvalidTask", "Endpoint must contain ASCII URL bytes");
	}
	const text = new TextDecoder().decode(value);
	let url: URL;
	try {
		url = new URL(text);
	} catch {
		throw new DAPError("InvalidTask", "Invalid endpoint URL");
	}
	if (
		(url.protocol !== "https:" &&
			!(allowInsecureHttp && url.protocol === "http:")) ||
		url.username ||
		url.password ||
		/[?#\\]/.test(text) ||
		/%(?![0-9a-f]{2})/i.test(text)
	) {
		throw new DAPError(
			"InvalidTask",
			"Expected an HTTPS endpoint without credentials, query, or fragment",
		);
	}
	// URL is used only for validation. Its normalized serialization must not
	// replace the representation authenticated in TaskConfiguration.
	return text;
}

function positiveSafe(value: bigint): number {
	if (value <= 0n || value > BigInt(Number.MAX_SAFE_INTEGER)) {
		throw new DAPError(
			"InvalidTask",
			"Task integer must be positive and exactly representable",
		);
	}
	return Number(value);
}

export class Task<M> {
	readonly id: string;
	readonly leader: string;
	readonly helper: string;
	readonly timePrecision: number;
	readonly minBatchSize: number;
	readonly batchMode = "time-interval" as const;
	readonly vdaf: ClientVdaf<M>;
	/** @internal Test compatibility; production tasks always use DAP 19. */
	readonly dapVersion: 18 | 19;
	#configuration: Uint8Array;
	#info: Uint8Array;
	#interval: { start: bigint; end: bigint } | undefined;

	private constructor(
		id: string,
		encoded: Uint8Array,
		configuration: TaskConfiguration,
		testOnly?: TaskOptions<unknown>["testOnly"],
	) {
		this.id = base64url(decodeId(id, 32));
		this.leader = endpoint(configuration.leader, testOnly?.allowInsecureHttp);
		this.helper = endpoint(configuration.helper, testOnly?.allowInsecureHttp);
		this.dapVersion = testOnly?.dapVersion ?? 19;
		this.timePrecision = positiveSafe(configuration.timePrecision);
		this.minBatchSize = positiveSafe(configuration.minBatchSize);
		if (configuration.batchMode !== 1 || configuration.batchConfig.length) {
			throw new DAPError(
				"InvalidTask",
				"Only time-interval batches are supported",
			);
		}
		let vdaf: ClientVdaf<unknown>;
		if (configuration.vdafType === 1 && !configuration.vdafConfig.length) {
			vdaf = prio3Count();
		} else if (
			configuration.vdafType === 2 &&
			configuration.vdafConfig.length === 8 &&
			!testOnly
		) {
			const limit = new Reader(configuration.vdafConfig).u64();
			try {
				vdaf = prio3Sum(limit);
			} catch (cause) {
				throw new DAPError("InvalidTask", "Invalid Prio3Sum bound", { cause });
			}
		} else if (
			configuration.vdafType === 4 &&
			configuration.vdafConfig.length === 8 &&
			!testOnly
		) {
			const reader = new Reader(configuration.vdafConfig);
			try {
				vdaf = prio3Histogram(reader.uint(4), reader.uint(4));
			} catch (cause) {
				throw new DAPError("InvalidTask", "Invalid Prio3Histogram parameters", {
					cause,
				});
			}
		} else {
			throw new DAPError("UnsupportedVdaf", "Unsupported VDAF configuration");
		}
		for (const extension of configuration.extensions) {
			if (extension.type !== 1)
				throw new DAPError("InvalidTask", "Unrecognized task extension");
			const interval = new Reader(extension.data);
			const start = interval.u64();
			const duration = interval.u64();
			interval.end();
			if (duration === 0n || start + duration > 0xffffffffffffffffn) {
				throw new DAPError("InvalidTask", "Invalid task interval");
			}
			this.#interval = { start, end: start + duration };
		}
		this.vdaf = vdaf as ClientVdaf<M>;
		this.#info = configuration.info.slice();
		this.#configuration = encoded.slice();
		Object.freeze(this);
	}

	static create<M>(options: TaskOptions<M>): Task<M> {
		if (
			options.vdaf !== prio3Count() &&
			(options.vdaf?.type !== "prio3-sum" ||
				options.vdaf.maxMeasurement === undefined ||
				options.vdaf !== prio3Sum(options.vdaf.maxMeasurement) ||
				options.testOnly) &&
			(options.vdaf?.type !== "prio3-histogram" ||
				options.vdaf.length === undefined ||
				options.vdaf.chunkLength === undefined ||
				options.vdaf !==
					prio3Histogram(options.vdaf.length, options.vdaf.chunkLength) ||
				options.testOnly)
		)
			throw new DAPError("UnsupportedVdaf", "Use a built-in VDAF factory");
		if (options.batchMode !== "time-interval")
			throw new DAPError("InvalidTask", "Unsupported batch mode");
		if (
			!Number.isSafeInteger(options.timePrecision) ||
			!Number.isSafeInteger(options.minBatchSize)
		) {
			throw new DAPError(
				"InvalidTask",
				"Task integers must be exactly representable",
			);
		}
		if (
			typeof options.leader !== "string" ||
			typeof options.helper !== "string"
		) {
			throw new DAPError("InvalidTask", "Endpoints must be strings");
		}
		const text = new TextEncoder();
		const configuration: TaskConfiguration = {
			info:
				typeof options.info === "string"
					? text.encode(options.info)
					: bytes(options.info ?? new Uint8Array()),
			leader: text.encode(options.leader),
			helper: text.encode(options.helper),
			timePrecision: BigInt(options.timePrecision),
			minBatchSize: BigInt(options.minBatchSize),
			batchMode: 1,
			batchConfig: new Uint8Array(),
			vdafType:
				options.vdaf.type === "prio3-count"
					? 1
					: options.vdaf.type === "prio3-sum"
						? 2
						: 4,
			vdafConfig:
				options.vdaf.type === "prio3-count"
					? new Uint8Array()
					: options.vdaf.type === "prio3-sum"
						? uint(options.vdaf.maxMeasurement!, 8)
						: concat(
								uint(options.vdaf.length!, 4),
								uint(options.vdaf.chunkLength!, 4),
							),
			extensions: options.extensions ?? [],
		};
		return new Task<M>(
			options.id,
			encodeTaskConfiguration(configuration),
			configuration,
			options.testOnly,
		);
	}

	static decode(input: EncodedTask, options?: DecodeOptions): Task<unknown> {
		const encoded = bytes(input.configuration).slice();
		return new Task(
			input.id,
			encoded,
			decodeTaskConfiguration(encoded, options),
		);
	}

	expect<N>(vdaf: ClientVdaf<N>): Task<N> {
		if ((vdaf as unknown) !== this.vdaf)
			throw new DAPError("UnsupportedVdaf", "Task VDAF does not match");
		return this as unknown as Task<N>;
	}

	get info(): Uint8Array {
		return this.#info.slice();
	}
	encodeConfiguration(): Uint8Array {
		return this.#configuration.slice();
	}

	/** Validate a timestamp expressed in DAP time-precision units. */
	validateTime(time: number): void {
		if (
			!Number.isSafeInteger(time) ||
			time < 0 ||
			(this.#interval &&
				(BigInt(time) < this.#interval.start ||
					BigInt(time) >= this.#interval.end))
		) {
			throw new DAPError(
				"InvalidReport",
				"Report time is outside the task interval",
			);
		}
	}
}
