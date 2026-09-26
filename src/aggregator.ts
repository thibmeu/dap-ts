import { bytes, concat, decodeId, Reader, uint, vector } from "./binary.js";
import { DAPError } from "./errors.js";
import { createSuite } from "./hpke.js";
import {
	encodeInputShareAad,
	encodeReportMetadata,
	type HpkeCiphertext,
	type Report,
	type ReportMetadata,
} from "./messages.js";
import { expand, mod, P, requireBytes } from "./prio3-count.js";
import { Task } from "./task.js";

const HALF = (P + 1n) / 2n;
const ROOT4 = 281474976710656n;
const suite = createSuite();

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
export function leaderCountInit(
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
export function helperCountInit(
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
export function leaderCountFinish(
	state: Uint8Array,
	inbound: Uint8Array,
): Uint8Array {
	const outputShare = elements(state, 1);
	readPingPong(inbound, 2, 0);
	return encoded(outputShare);
}

export interface AggregatorKey {
	readonly configId: number;
	readonly privateKey: Uint8Array | CryptoKey;
}

/** Encode a per-report DAP rejection after a host replay or collected-bucket check. */
export function encodeCountJobRejection(
	reportId: Uint8Array,
	code: number,
): Uint8Array {
	if (!Number.isInteger(code) || code < 1 || code > 10)
		throw new DAPError("InvalidMessage", "Invalid report error");
	return concat(bytes(reportId, 16), uint(2, 1), uint(code, 1));
}

/** Deserialize once at service startup to avoid repeating X25519 key setup per report. */
export async function prepareAggregatorKey(key: {
	readonly configId: number;
	readonly privateKey: Uint8Array;
}): Promise<{ configId: number; privateKey: CryptoKey }> {
	uint(key.configId, 1);
	return {
		configId: key.configId,
		privateKey: await suite.DeserializePrivateKey(bytes(key.privateKey, 32)),
	};
}

/** Decrypt and validate one DAP 19 Count input share. */
export async function openCountInputShare(
	task: Task<number>,
	role: "leader" | "helper",
	metadata: ReportMetadata,
	publicShare: Uint8Array,
	ciphertext: HpkeCiphertext,
	key: AggregatorKey,
): Promise<Uint8Array> {
	if (
		!(task instanceof Task) ||
		task.dapVersion !== 19 ||
		task.vdaf.type !== "prio3-count"
	) {
		throw new DAPError("InvalidTask", "Expected a DAP 19 Count task");
	}
	if (ciphertext.configId !== key.configId)
		throw new DAPError("InvalidHpkeConfig", "Unknown HPKE config ID");
	if (key.privateKey instanceof Uint8Array) bytes(key.privateKey, 32);
	bytes(metadata.id, 16);
	bytes(publicShare, 0);
	if (metadata.publicExtensions.length)
		throw new DAPError("InvalidReport", "Unsupported report extension");
	if (metadata.time > BigInt(Number.MAX_SAFE_INTEGER))
		throw new DAPError("InvalidReport", "Invalid report time");
	task.validateTime(Number(metadata.time));
	const taskId = decodeId(task.id, 32);
	const aad = encodeInputShareAad(
		taskId,
		task.encodeConfiguration(),
		metadata,
		publicShare,
	);
	const info = concat(
		new TextEncoder().encode("dap-19 input share"),
		Uint8Array.of(1, role === "leader" ? 2 : 3),
	);
	let plaintext: Uint8Array;
	try {
		const privateKey =
			key.privateKey instanceof Uint8Array
				? await suite.DeserializePrivateKey(key.privateKey)
				: key.privateKey;
		plaintext = await suite.Open(
			privateKey,
			ciphertext.enc,
			ciphertext.payload,
			{ info, aad },
		);
	} catch (cause) {
		throw new DAPError("DecryptionFailed", "Input share decryption failed", {
			cause,
		});
	}
	const reader = new Reader(plaintext);
	if (reader.vector(2).length)
		throw new DAPError("InvalidReport", "Unsupported private extension");
	const share = reader.vector(4, 1);
	reader.end();
	try {
		if (role === "leader") elements(share, 6);
		else bytes(share, 32);
	} catch (cause) {
		throw new DAPError("InvalidReport", "Invalid Count input share", { cause });
	}
	return share;
}

function context(task: Task<number>): Uint8Array {
	return concat(new TextEncoder().encode("dap-19"), decodeId(task.id, 32));
}

/** Build one DAP 19 aggregation initialization request; persist the returned bytes for retries. */
export async function leaderCountJobInit(
	task: Task<number>,
	report: Report,
	key: AggregatorKey,
	verificationKeyId: number,
	verifyKey: Uint8Array,
): Promise<{
	request: Uint8Array;
	state: Uint8Array;
	reportId: Uint8Array;
	time: bigint;
}> {
	const input = await openCountInputShare(
		task,
		"leader",
		report.metadata,
		report.publicShare,
		report.leader,
		key,
	);
	const { state, outbound } = leaderCountInit(
		verifyKey,
		context(task),
		report.metadata.id,
		report.publicShare,
		input,
	);
	const helper = report.helper;
	const request = concat(
		uint(verificationKeyId, 1),
		vector(new Uint8Array(), 4),
		vector(new Uint8Array(), 2),
		encodeReportMetadata(report.metadata),
		vector(report.publicShare, 4),
		uint(helper.configId, 1),
		vector(helper.enc, 2, 1),
		vector(helper.payload, 4, 1),
		vector(outbound, 4, 1),
	);
	return {
		request,
		state,
		reportId: report.metadata.id.slice(),
		time: report.metadata.time,
	};
}

/** Process one request. Commit and cache the returned response atomically in the host before sending it. */
export async function helperCountJobInit(
	task: Task<number>,
	request: Uint8Array,
	key: AggregatorKey,
	verificationKeyId: number,
	verifyKey: Uint8Array,
): Promise<{
	response: Uint8Array;
	reportId: Uint8Array;
	time: bigint;
	outputShare?: Uint8Array;
}> {
	const reader = new Reader(request);
	const selectedKey = reader.uint(1);
	if (reader.vector(4).length || reader.vector(2).length)
		throw new DAPError(
			"InvalidMessage",
			"Expected empty Count parameter and job extensions",
		);
	const metadata = {
		id: reader.take(16),
		time: reader.u64(),
		publicExtensions: [],
	};
	if (reader.vector(2).length)
		throw new DAPError("InvalidMessage", "Unsupported report extension");
	const publicShare = reader.vector(4);
	const ciphertext = {
		configId: reader.uint(1),
		enc: reader.vector(2, 1),
		payload: reader.vector(4, 1),
	};
	const inbound = reader.vector(4, 1);
	reader.end();
	const reject = (code: number) => ({
		response: encodeCountJobRejection(metadata.id, code),
		reportId: metadata.id,
		time: metadata.time,
	});
	if (selectedKey !== verificationKeyId) return reject(9);
	let input: Uint8Array;
	try {
		input = await openCountInputShare(
			task,
			"helper",
			metadata,
			publicShare,
			ciphertext,
			key,
		);
	} catch (cause) {
		if (cause instanceof DAPError && cause.code === "InvalidHpkeConfig")
			return reject(4);
		if (cause instanceof DAPError && cause.code === "DecryptionFailed")
			return reject(5);
		return reject(7);
	}
	try {
		const { outputShare, outbound } = helperCountInit(
			verifyKey,
			context(task),
			metadata.id,
			publicShare,
			input,
			inbound,
		);
		return {
			response: concat(metadata.id, Uint8Array.of(0), vector(outbound, 4, 1)),
			reportId: metadata.id,
			time: metadata.time,
			outputShare,
		};
	} catch {
		return reject(6);
	}
}

/** Parse the Helper's response and finish the Leader's Count verification. */
export function leaderCountJobFinish(
	state: Uint8Array,
	reportId: Uint8Array,
	response: Uint8Array,
): { outputShare: Uint8Array } | { reportError: number } {
	const reader = new Reader(response);
	const receivedId = reader.take(16);
	if (!bytes(reportId, 16).every((byte, i) => byte === receivedId[i]))
		throw new DAPError("InvalidMessage", "Wrong report ID");
	const type = reader.uint(1);
	if (type === 2) {
		const reportError = reader.uint(1);
		reader.end();
		if (reportError < 1 || reportError > 10)
			throw new DAPError("InvalidMessage", "Unknown report error");
		return { reportError };
	}
	if (type !== 0)
		throw new DAPError("InvalidMessage", "Expected continuation or rejection");
	const inbound = reader.vector(4, 1);
	reader.end();
	return { outputShare: leaderCountFinish(state, inbound) };
}

export type CountLeaderJob = Awaited<ReturnType<typeof leaderCountJobInit>>;
export type CountHelperJob = Awaited<ReturnType<typeof helperCountJobInit>>;

/** Task-scoped Leader storage. Writes are atomic; reads return owned snapshots. */
export interface CountLeaderStore {
	/** Resume a pending job without decrypting the report again. */
	loadLeader(
		jobId: string,
	): CountLeaderJob | undefined | Promise<CountLeaderJob | undefined>;
	/** Persist the exact request and state before sending. Identical retries return saved bytes. */
	saveLeader(
		jobId: string,
		job: CountLeaderJob,
	): CountLeaderJob | Promise<CountLeaderJob>;
	/** Validate the saved state, claim the report, add its share, and release the bucket reservation. */
	commitLeader(
		jobId: string,
		response: Uint8Array,
	): Uint8Array | undefined | Promise<Uint8Array | undefined>;
}

/** Task-scoped Helper storage. A success response is safe to send only after commit. */
export interface CountHelperStore {
	/** Return a committed response for identical request bytes; fail on a job ID conflict. */
	loadHelper(
		jobId: string,
		request: Uint8Array,
	): Uint8Array | undefined | Promise<Uint8Array | undefined>;
	/** Atomically check job bytes, replay and collection state, add one share, and cache the response. */
	commitHelper(
		jobId: string,
		request: Uint8Array,
		result: CountHelperJob,
	): Uint8Array | Promise<Uint8Array>;
}
