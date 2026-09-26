import {
	addFieldOutputShare,
	histogramVerifierMessage,
	histogramVerifierShare,
	sumVerifierMessage,
	sumVerifierShare,
} from "./aggregator-prio3.js";

export {
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
import { createSuite, prepareRecipientKey } from "./hpke.js";
import {
	encodeInputShareAad,
	encodeReportMetadata,
	type HpkeCiphertext,
	type Report,
	type ReportMetadata,
} from "./messages.js";
import { expand, mod, P, requireBytes } from "./prio3-count.js";
import { P128 } from "./prio3-histogram.js";
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
	readonly privateKey: Uint8Array | CryptoKey | CryptoKeyPair;
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
}): Promise<{ configId: number; privateKey: CryptoKeyPair }> {
	uint(key.configId, 1);
	return {
		configId: key.configId,
		privateKey: await prepareRecipientKey(key.privateKey),
	};
}

function shareLength(task: Task<unknown>, role: "leader" | "helper"): number {
	if (role === "helper") return task.vdaf.type === "prio3-histogram" ? 64 : 32;
	if (task.vdaf.type === "prio3-count") return 48;
	if (task.vdaf.type === "prio3-sum") {
		const bits = task.vdaf.maxMeasurement!.toString(2).length;
		let p = 1;
		while (p <= bits) p *= 2;
		return 8 * (bits + 2 * p);
	}
	const { length, chunkLength } = task.vdaf;
	const calls = Math.ceil(length! / chunkLength!);
	let p = 1;
	while (p <= calls) p *= 2;
	return 16 * (length! + 2 * chunkLength! + 2 * p - 1) + 32;
}

function requirePrio3Task(task: Task<unknown>): void {
	if (
		!(task instanceof Task) ||
		task.dapVersion !== 19 ||
		!["prio3-count", "prio3-sum", "prio3-histogram"].includes(task.vdaf.type)
	)
		throw new DAPError("InvalidTask", "Expected a DAP 19 Prio3 task");
}

/** Decrypt and validate one DAP 19 Prio3 input share. */
export async function openPrio3InputShare(
	task: Task<unknown>,
	role: "leader" | "helper",
	metadata: ReportMetadata,
	publicShare: Uint8Array,
	ciphertext: HpkeCiphertext,
	key: AggregatorKey,
	nowMs = Date.now(),
): Promise<Uint8Array> {
	requirePrio3Task(task);
	if (ciphertext.configId !== key.configId)
		throw new DAPError("InvalidHpkeConfig", "Unknown HPKE config ID");
	if (key.privateKey instanceof Uint8Array) bytes(key.privateKey, 32);
	bytes(metadata.id, 16);
	bytes(publicShare, task.vdaf.type === "prio3-histogram" ? 64 : 0);
	if (metadata.publicExtensions.length)
		throw new DAPError("InvalidReport", "Unsupported report extension");
	if (metadata.time > BigInt(Number.MAX_SAFE_INTEGER))
		throw new DAPError("InvalidReport", "Invalid report time");
	if (!Number.isSafeInteger(nowMs) || nowMs < 0)
		throw new DAPError("InvalidMessage", "Invalid current time");
	if (
		metadata.time * BigInt(task.timePrecision) >
		BigInt(Math.floor(nowMs / 1000)) + 300n
	)
		throw new DAPError(
			"ReportTooEarly",
			"Report time is too far in the future",
		);
	try {
		task.validateTime(Number(metadata.time));
	} catch (cause) {
		throw new DAPError("ReportDropped", "Report is outside the task interval", {
			cause,
		});
	}
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
				? await prepareRecipientKey(key.privateKey)
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
		bytes(share, shareLength(task, role));
		if (role === "leader") {
			if (task.vdaf.type === "prio3-count") elements(share, 6);
			else if (task.vdaf.type === "prio3-sum") {
				for (let offset = 0; offset < share.length; offset += 8)
					elements(share.subarray(offset, offset + 8), 1);
			} else {
				const view = new DataView(
					share.buffer,
					share.byteOffset,
					share.byteLength,
				);
				for (let offset = 0; offset < share.length - 32; offset += 16) {
					const value =
						view.getBigUint64(offset, true) |
						(view.getBigUint64(offset + 8, true) << 64n);
					if (value >= P128)
						throw new RangeError("Non-canonical Field128 element");
				}
			}
		}
	} catch (cause) {
		throw new DAPError("InvalidReport", "Invalid Prio3 input share", { cause });
	}
	return share;
}

export async function openCountInputShare(
	task: Task<number>,
	role: "leader" | "helper",
	metadata: ReportMetadata,
	publicShare: Uint8Array,
	ciphertext: HpkeCiphertext,
	key: AggregatorKey,
	nowMs = Date.now(),
): Promise<Uint8Array> {
	if (task.vdaf.type !== "prio3-count")
		throw new DAPError("InvalidTask", "Expected a Count task");
	return openPrio3InputShare(
		task,
		role,
		metadata,
		publicShare,
		ciphertext,
		key,
		nowMs,
	);
}

function context(task: Task<unknown>): Uint8Array {
	return concat(new TextEncoder().encode("dap-19"), decodeId(task.id, 32));
}

function leaderPrio3Init(
	task: Task<unknown>,
	verifyKey: Uint8Array,
	nonce: Uint8Array,
	publicShare: Uint8Array,
	inputShare: Uint8Array,
): { state: Uint8Array; outbound: Uint8Array } {
	const ctx = context(task);
	if (task.vdaf.type === "prio3-count")
		return leaderCountInit(verifyKey, ctx, nonce, publicShare, inputShare);
	if (task.vdaf.type === "prio3-sum") {
		const share = sumVerifierShare(
			0,
			task.vdaf.maxMeasurement!,
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
		task.vdaf.length!,
		task.vdaf.chunkLength!,
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

function helperPrio3Init(
	task: Task<unknown>,
	verifyKey: Uint8Array,
	nonce: Uint8Array,
	publicShare: Uint8Array,
	inputShare: Uint8Array,
	inbound: Uint8Array,
): { outputShare: Uint8Array; outbound: Uint8Array } {
	const ctx = context(task);
	if (task.vdaf.type === "prio3-count")
		return helperCountInit(
			verifyKey,
			ctx,
			nonce,
			publicShare,
			inputShare,
			inbound,
		);
	if (task.vdaf.type === "prio3-sum") {
		const leaderShare = readPingPong(inbound, 0, 24);
		const helper = sumVerifierShare(
			1,
			task.vdaf.maxMeasurement!,
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
	const chunkLength = task.vdaf.chunkLength!;
	const leaderShare = readPingPong(inbound, 0, (2 * chunkLength + 2) * 16 + 32);
	const helper = histogramVerifierShare(
		1,
		task.vdaf.length!,
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

function leaderPrio3Finish(
	task: Task<unknown>,
	state: Uint8Array,
	inbound: Uint8Array,
): Uint8Array {
	if (task.vdaf.type === "prio3-count")
		return leaderCountFinish(state, inbound);
	if (task.vdaf.type === "prio3-sum") {
		bytes(state, 8);
		readPingPong(inbound, 2, 0);
		return state.slice();
	}
	const length = task.vdaf.length! * 16;
	bytes(state, length + 32);
	const message = readPingPong(inbound, 2, 32);
	if (!message.every((byte, i) => byte === state[length + i]))
		throw new RangeError("Prio3Histogram joint randomness mismatch");
	return state.slice(0, length);
}

function countJobHeader(verificationKeyId: number): Uint8Array {
	return concat(
		uint(verificationKeyId, 1),
		vector(new Uint8Array(), 4),
		vector(new Uint8Array(), 2),
	);
}

/** Build one DAP 19 Prio3 aggregation initialization request. */
export async function leaderPrio3JobInit(
	task: Task<unknown>,
	report: Report,
	key: AggregatorKey,
	verificationKeyId: number,
	verifyKey: Uint8Array,
	nowMs = Date.now(),
): Promise<{
	request: Uint8Array;
	state: Uint8Array;
	reportId: Uint8Array;
	time: bigint;
}> {
	const input = await openPrio3InputShare(
		task,
		"leader",
		report.metadata,
		report.publicShare,
		report.leader,
		key,
		nowMs,
	);
	const { state, outbound } = leaderPrio3Init(
		task,
		verifyKey,
		report.metadata.id,
		report.publicShare,
		input,
	);
	const helper = report.helper;
	const request = concat(
		countJobHeader(verificationKeyId),
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

/** Count-compatible one-report entry point. */
export async function leaderCountJobInit(
	task: Task<number>,
	report: Report,
	key: AggregatorKey,
	verificationKeyId: number,
	verifyKey: Uint8Array,
	nowMs = Date.now(),
): Promise<{
	request: Uint8Array;
	state: Uint8Array;
	reportId: Uint8Array;
	time: bigint;
}> {
	if (task.vdaf.type !== "prio3-count")
		throw new DAPError("InvalidTask", "Expected a Count task");
	return leaderPrio3JobInit(
		task,
		report,
		key,
		verificationKeyId,
		verifyKey,
		nowMs,
	);
}

/** Build one job from distinct Prio3 reports, keeping per-report validation failures. */
export async function leaderPrio3BatchInit(
	task: Task<unknown>,
	reports: readonly Report[],
	key: AggregatorKey,
	verificationKeyId: number,
	verifyKey: Uint8Array,
	nowMs = Date.now(),
): Promise<{
	request: Uint8Array;
	reports: { reportId: Uint8Array; time: bigint; state: Uint8Array }[];
	rejected: { reportId: Uint8Array; error: DAPError }[];
}> {
	if (!reports.length)
		throw new DAPError("InvalidMessage", "Expected at least one report");
	const seen = new Set<string>();
	const ready = [];
	const rejected = [];
	const header = countJobHeader(verificationKeyId);
	const requestParts = [header];
	for (const report of reports) {
		const reportId = bytes(report.metadata.id, 16);
		const id = base64url(reportId);
		if (seen.has(id))
			throw new DAPError("InvalidMessage", "Duplicate report ID in job");
		seen.add(id);
		try {
			const job = await leaderPrio3JobInit(
				task,
				report,
				key,
				verificationKeyId,
				verifyKey,
				nowMs,
			);
			ready.push({ reportId: job.reportId, time: job.time, state: job.state });
			requestParts.push(job.request.subarray(header.length));
		} catch (error) {
			if (
				!(error instanceof DAPError) ||
				![
					"InvalidHpkeConfig",
					"DecryptionFailed",
					"InvalidReport",
					"ReportTooEarly",
					"ReportDropped",
				].includes(error.code)
			)
				throw error;
			rejected.push({ reportId: reportId.slice(), error });
		}
	}
	return { request: concatParts(requestParts), reports: ready, rejected };
}

export async function leaderCountBatchInit(
	task: Task<number>,
	reports: readonly Report[],
	key: AggregatorKey,
	verificationKeyId: number,
	verifyKey: Uint8Array,
	nowMs = Date.now(),
): ReturnType<typeof leaderPrio3BatchInit> {
	if (task.vdaf.type !== "prio3-count")
		throw new DAPError("InvalidTask", "Expected a Count task");
	return leaderPrio3BatchInit(
		task,
		reports,
		key,
		verificationKeyId,
		verifyKey,
		nowMs,
	);
}

/** Verify each Prio3 report in a job. The host commits and caches the response atomically. */
export async function helperPrio3BatchInit(
	task: Task<unknown>,
	request: Uint8Array,
	key: AggregatorKey,
	verificationKeyId: number,
	verifyKey: Uint8Array,
	nowMs = Date.now(),
): Promise<{
	response: Uint8Array;
	reports: {
		response: Uint8Array;
		reportId: Uint8Array;
		time: bigint;
		outputShare?: Uint8Array;
	}[];
}> {
	requirePrio3Task(task);
	const reader = new Reader(request);
	const selectedKey = reader.uint(1);
	if (reader.vector(4).length || reader.vector(2).length)
		throw new DAPError(
			"InvalidMessage",
			"Expected empty Prio3 parameter and job extensions",
		);
	const entries = [];
	const seen = new Set<string>();
	while (reader.remaining) {
		const metadata = {
			id: reader.take(16),
			time: reader.u64(),
			publicExtensions: [],
		};
		const id = base64url(metadata.id);
		if (seen.has(id))
			throw new DAPError("InvalidMessage", "Duplicate report ID in job");
		seen.add(id);
		entries.push({
			metadata,
			unsupportedPublicExtension: reader.vector(2).length > 0,
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
	const results = [];
	for (const entry of entries) {
		const { metadata, publicShare, ciphertext, inbound } = entry;
		const reject = (code: number) => ({
			response: encodeCountJobRejection(metadata.id, code),
			reportId: metadata.id,
			time: metadata.time,
		});
		if (selectedKey !== verificationKeyId) {
			results.push(reject(9));
			continue;
		}
		if (entry.unsupportedPublicExtension) {
			results.push(reject(7));
			continue;
		}
		let input: Uint8Array;
		try {
			input = await openPrio3InputShare(
				task,
				"helper",
				metadata,
				publicShare,
				ciphertext,
				key,
				nowMs,
			);
		} catch (cause) {
			const code =
				cause instanceof DAPError && cause.code === "InvalidHpkeConfig"
					? 4
					: cause instanceof DAPError && cause.code === "DecryptionFailed"
						? 5
						: cause instanceof DAPError && cause.code === "ReportTooEarly"
							? 8
							: cause instanceof DAPError && cause.code === "ReportDropped"
								? 3
								: 7;
			results.push(reject(code));
			continue;
		}
		try {
			const { outputShare, outbound } = helperPrio3Init(
				task,
				verifyKey,
				metadata.id,
				publicShare,
				input,
				inbound,
			);
			results.push({
				response: concat(metadata.id, Uint8Array.of(0), vector(outbound, 4, 1)),
				reportId: metadata.id,
				time: metadata.time,
				outputShare,
			});
		} catch {
			results.push(reject(6));
		}
	}
	return {
		response: concatParts(results.map((result) => result.response)),
		reports: results,
	};
}

export async function helperCountBatchInit(
	task: Task<number>,
	request: Uint8Array,
	key: AggregatorKey,
	verificationKeyId: number,
	verifyKey: Uint8Array,
	nowMs = Date.now(),
): ReturnType<typeof helperPrio3BatchInit> {
	if (task.vdaf.type !== "prio3-count")
		throw new DAPError("InvalidTask", "Expected a Count task");
	return helperPrio3BatchInit(
		task,
		request,
		key,
		verificationKeyId,
		verifyKey,
		nowMs,
	);
}

/** Process a one-report job. */
export async function helperCountJobInit(
	task: Task<number>,
	request: Uint8Array,
	key: AggregatorKey,
	verificationKeyId: number,
	verifyKey: Uint8Array,
	nowMs = Date.now(),
): Promise<{
	response: Uint8Array;
	reportId: Uint8Array;
	time: bigint;
	outputShare?: Uint8Array;
}> {
	const job = await helperCountBatchInit(
		task,
		request,
		key,
		verificationKeyId,
		verifyKey,
		nowMs,
	);
	if (job.reports.length !== 1)
		throw new DAPError("InvalidMessage", "Expected one report");
	return job.reports[0]!;
}

type FinishedReport = { outputShare: Uint8Array } | { reportError: number };
type PendingReport = {
	readonly reportId: Uint8Array;
	readonly time: bigint;
	readonly state: Uint8Array;
};

function finishJob(
	state: Uint8Array,
	reportId: Uint8Array,
	response: Uint8Array,
	finish: (state: Uint8Array, inbound: Uint8Array) => Uint8Array,
): FinishedReport {
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
	return { outputShare: finish(state, inbound) };
}

/** Parse the Helper's response and finish the Leader's Count verification. */
export function leaderCountJobFinish(
	state: Uint8Array,
	reportId: Uint8Array,
	response: Uint8Array,
): FinishedReport {
	return finishJob(state, reportId, response, leaderCountFinish);
}

/** Finish one Prio3 report after checking the Helper's report ID and response. */
export function leaderPrio3JobFinish(
	task: Task<unknown>,
	state: Uint8Array,
	reportId: Uint8Array,
	response: Uint8Array,
): FinishedReport {
	requirePrio3Task(task);
	return finishJob(state, reportId, response, (stored, inbound) =>
		leaderPrio3Finish(task, stored, inbound),
	);
}

function finishBatch(
	reports: readonly PendingReport[],
	response: Uint8Array,
	finish: (
		state: Uint8Array,
		reportId: Uint8Array,
		record: Uint8Array,
	) => FinishedReport,
): ({ reportId: Uint8Array; time: bigint } & FinishedReport)[] {
	if (!reports.length)
		throw new DAPError("InvalidMessage", "Expected at least one report");
	const reader = new Reader(response);
	const results = [];
	for (const report of reports) {
		const id = reader.take(16);
		const type = reader.uint(1);
		let record: Uint8Array;
		if (type === 2) record = concat(id, uint(type, 1), uint(reader.uint(1), 1));
		else if (type === 0)
			record = concat(id, uint(type, 1), vector(reader.vector(4, 1), 4, 1));
		else throw new DAPError("InvalidMessage", "Unexpected response type");
		results.push({
			reportId: report.reportId,
			time: report.time,
			...finish(report.state, report.reportId, record),
		});
	}
	reader.end();
	return results;
}

/** Finish a Prio3 batch in response order. */
export function leaderPrio3BatchFinish(
	task: Task<unknown>,
	reports: readonly PendingReport[],
	response: Uint8Array,
): ({ reportId: Uint8Array; time: bigint } & FinishedReport)[] {
	requirePrio3Task(task);
	return finishBatch(reports, response, (state, reportId, record) =>
		leaderPrio3JobFinish(task, state, reportId, record),
	);
}

/** Finish every Count report in response order. */
export function leaderCountBatchFinish(
	reports: readonly PendingReport[],
	response: Uint8Array,
): ({ reportId: Uint8Array; time: bigint } & FinishedReport)[] {
	return finishBatch(reports, response, leaderCountJobFinish);
}

/** Add a verified Count output share to a stored aggregate share. */
export function addCountOutputShare(
	current: Uint8Array,
	next: Uint8Array,
): Uint8Array {
	return encoded([mod(elements(current, 1)[0]! + elements(next, 1)[0]!)]);
}

/** Add canonical output shares for the task's Prio3 field and output length. */
export function addPrio3OutputShare(
	task: Task<unknown>,
	current: Uint8Array,
	next: Uint8Array,
): Uint8Array {
	requirePrio3Task(task);
	const width = task.vdaf.type === "prio3-histogram" ? 16 : 8;
	const length =
		task.vdaf.type === "prio3-histogram" ? task.vdaf.length! * 16 : 8;
	bytes(current, length);
	bytes(next, length);
	return addFieldOutputShare(current, next, width);
}
