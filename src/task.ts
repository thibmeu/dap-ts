import { base64url, bytes, decodeId, Reader } from "./binary.js";
import { DAPError } from "./errors.js";
import {
	type DecodeOptions,
	decodeTaskConfiguration,
	type Extension,
	encodeTaskConfiguration,
	type TaskConfiguration,
} from "./messages.js";
import {
	checkVdaf,
	decodeVdaf,
	encodeVdaf,
	sameVdaf,
	type Vdaf,
} from "./vdaf.js";

export interface TaskOptions<V extends Vdaf> {
	readonly id: string;
	readonly info?: string | Uint8Array;
	readonly leader: string;
	readonly helper: string;
	/** Seconds per DAP time unit. Report times and batch buckets use it. */
	readonly timePrecision: number;
	readonly minBatchSize: number;
	readonly batchMode: "time-interval";
	readonly vdaf: V;
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

export class Task<V extends Vdaf = Vdaf> {
	readonly id: string;
	readonly leader: string;
	readonly helper: string;
	readonly timePrecision: number;
	readonly minBatchSize: number;
	readonly batchMode = "time-interval" as const;
	readonly vdaf: V;
	/** @internal Test compatibility; production tasks always use DAP 19. */
	readonly dapVersion: 18 | 19;
	#configuration: Uint8Array;
	#info: Uint8Array;
	#interval: { start: bigint; end: bigint } | undefined;

	private constructor(
		id: string,
		encoded: Uint8Array,
		configuration: TaskConfiguration,
		testOnly?: TaskOptions<Vdaf>["testOnly"],
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
		let vdaf: Vdaf | undefined;
		try {
			vdaf = decodeVdaf(configuration.vdafType, configuration.vdafConfig);
		} catch (cause) {
			throw new DAPError("InvalidTask", "Invalid VDAF parameters", { cause });
		}
		// The DAP 18 test-only profile covers Count alone.
		if (!vdaf || (testOnly && vdaf.type !== "prio3-count"))
			throw new DAPError("UnsupportedVdaf", "Unsupported VDAF configuration");
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
		this.vdaf = vdaf as V;
		this.#info = configuration.info.slice();
		this.#configuration = encoded.slice();
		Object.freeze(this);
	}

	static create<V extends Vdaf>(options: TaskOptions<V>): Task<V> {
		let vdaf: Vdaf;
		try {
			vdaf = checkVdaf(options.vdaf);
		} catch (cause) {
			throw new DAPError("UnsupportedVdaf", "Invalid VDAF configuration", {
				cause,
			});
		}
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
		const { type, config } = encodeVdaf(vdaf);
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
			vdafType: type,
			vdafConfig: config,
			extensions: options.extensions ?? [],
		};
		return new Task<V>(
			options.id,
			encodeTaskConfiguration(configuration),
			configuration,
			options.testOnly,
		);
	}

	/** Read a provisioned task. Narrow its VDAF with `expect()`. */
	static decode(input: EncodedTask, options?: DecodeOptions): Task {
		const encoded = bytes(input.configuration).slice();
		return new Task(
			input.id,
			encoded,
			decodeTaskConfiguration(encoded, options),
		);
	}

	expect<W extends Vdaf>(vdaf: W): Task<W> {
		if (!sameVdaf(vdaf, this.vdaf))
			throw new DAPError("UnsupportedVdaf", "Task VDAF does not match");
		return this as unknown as Task<W>;
	}

	get info(): Uint8Array<ArrayBuffer> {
		return this.#info.slice();
	}
	encodeConfiguration(): Uint8Array<ArrayBuffer> {
		return this.#configuration.slice();
	}

	/** @internal Whether a time in DAP time-precision units is in the task interval. */
	inInterval(time: bigint): boolean {
		return (
			!this.#interval ||
			(time >= this.#interval.start && time < this.#interval.end)
		);
	}
}

/** @internal Truncate Unix milliseconds to DAP time-precision units. */
export function toTime(task: Task, ms: number): bigint {
	if (!Number.isSafeInteger(ms) || ms < 0)
		throw new DAPError(
			"InvalidMessage",
			"Expected non-negative Unix milliseconds",
		);
	return BigInt(ms) / (1000n * BigInt(task.timePrecision));
}

/** @internal Convert DAP time-precision units to Unix milliseconds. */
export function toMs(task: Task, time: bigint): number {
	const ms = time * 1000n * BigInt(task.timePrecision);
	if (ms > BigInt(Number.MAX_SAFE_INTEGER))
		throw new DAPError("InvalidMessage", "Time is beyond the supported range");
	return Number(ms);
}
