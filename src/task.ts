import { base64url, bytes, decodeId, Reader } from "./binary.js";
import { DAPError } from "./errors.js";
import {
	type DecodeOptions,
	decodeTaskConfiguration,
	type Extension,
	encodeTaskConfiguration,
	type TaskConfiguration,
} from "./messages.js";
import { type ClientVdaf, prio3Count } from "./prio3-count.js";

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
}
export interface EncodedTask {
	readonly id: string;
	readonly configuration: Uint8Array;
}

function endpoint(value: Uint8Array): string {
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
		url.protocol !== "https:" ||
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
	#configuration: Uint8Array;
	#info: Uint8Array;
	#interval: { start: bigint; end: bigint } | undefined;

	private constructor(
		id: string,
		encoded: Uint8Array,
		configuration: TaskConfiguration,
	) {
		this.id = base64url(decodeId(id, 32));
		this.leader = endpoint(configuration.leader);
		this.helper = endpoint(configuration.helper);
		this.timePrecision = positiveSafe(configuration.timePrecision);
		this.minBatchSize = positiveSafe(configuration.minBatchSize);
		if (configuration.batchMode !== 1 || configuration.batchConfig.length) {
			throw new DAPError(
				"InvalidTask",
				"Only time-interval batches are supported",
			);
		}
		if (configuration.vdafType !== 1 || configuration.vdafConfig.length) {
			throw new DAPError(
				"UnsupportedVdaf",
				"Expected Prio3Count with empty configuration",
			);
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
		this.vdaf = prio3Count() as ClientVdaf<M>;
		this.#info = configuration.info.slice();
		this.#configuration = encoded.slice();
		Object.freeze(this);
	}

	static create<M>(options: TaskOptions<M>): Task<M> {
		if (options.vdaf !== prio3Count())
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
			vdafType: 1,
			vdafConfig: new Uint8Array(),
			extensions: options.extensions ?? [],
		};
		return new Task<M>(
			options.id,
			encodeTaskConfiguration(configuration),
			configuration,
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
		if (vdaf !== prio3Count())
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
