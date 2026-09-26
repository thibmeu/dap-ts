import { expect, it } from "vitest";
import {
	encodeCountJobRejection,
	helperCountJobInit,
	leaderCountJobFinish,
	leaderCountJobInit,
	prepareAggregatorKey,
} from "../src/aggregator.js";
import { DAPClient } from "../src/client.js";
import { decodeReport, encodeReport } from "../src/messages.js";
import { P, unshardCount } from "../src/prio3-count.js";
import { deterministicRandom, hpke, task } from "./fixtures.js";
import hpkeVector from "./vectors/hpke-rfc9180-a1.json";

type CountLeaderJob = Awaited<ReturnType<typeof leaderCountJobInit>>;
type CountHelperJob = Awaited<ReturnType<typeof helperCountJobInit>>;

// One synchronous method stands in for each database transaction. A real store
// needs unique report/job indexes and a transaction around these same checks.
class MemoryStore {
	jobs = new Map<
		string,
		{ request: Uint8Array; response?: Uint8Array; leader?: CountLeaderJob }
	>();
	reports = new Set<string>();
	buckets = new Map<
		bigint,
		{ sum: bigint; count: number; collected: boolean; pending: number }
	>();

	bucket(time: bigint) {
		const start = time - (time % BigInt(task.timePrecision));
		let value = this.buckets.get(start);
		if (!value) {
			value = { sum: 0n, count: 0, collected: false, pending: 0 };
			this.buckets.set(start, value);
		}
		return value;
	}

	loadLeader(jobId: string): CountLeaderJob | undefined {
		const job = this.jobs.get(jobId)?.leader;
		return (
			job && {
				request: job.request.slice(),
				state: job.state.slice(),
				reportId: job.reportId.slice(),
				time: job.time,
			}
		);
	}

	loadHelper(jobId: string, request: Uint8Array): Uint8Array | undefined {
		const job = this.jobs.get(jobId);
		if (!job) return undefined;
		if (!same(job.request, request)) throw new Error("job identity conflict");
		return job.response?.slice();
	}

	saveLeader(jobId: string, job: CountLeaderJob): CountLeaderJob {
		const prior = this.jobs.get(jobId);
		if (prior) {
			if (!prior.leader || !same(prior.request, job.request))
				throw new Error("job identity conflict");
			return this.loadLeader(jobId)!;
		}
		const reportId = job.reportId.toHex();
		const bucket = this.bucket(job.time);
		if (this.reports.has(reportId) || bucket.collected)
			throw new Error("report cannot be committed");
		bucket.pending++;
		const saved = {
			request: job.request.slice(),
			state: job.state.slice(),
			reportId: job.reportId.slice(),
			time: job.time,
		};
		this.jobs.set(jobId, { request: saved.request, leader: saved });
		return saved;
	}

	commitHelper(
		jobId: string,
		request: Uint8Array,
		result: CountHelperJob,
	): Uint8Array {
		const prior = this.jobs.get(jobId);
		if (prior) {
			return this.loadHelper(jobId, request)!;
		}
		const bucket = this.bucket(result.time);
		const reportId = result.reportId.toHex();
		let response = result.response;
		if (result.outputShare) {
			if (this.reports.has(reportId))
				response = encodeCountJobRejection(result.reportId, 2);
			else if (bucket.collected)
				response = encodeCountJobRejection(result.reportId, 1);
			else {
				this.reports.add(reportId);
				add(bucket, result.outputShare);
			}
		}
		this.jobs.set(jobId, {
			request: request.slice(),
			response: response.slice(),
		});
		return response.slice();
	}

	commitLeader(jobId: string, response: Uint8Array): Uint8Array | undefined {
		const job = this.jobs.get(jobId);
		if (!job?.leader) throw new Error("missing leader state");
		if (job.response) {
			if (!same(job.response, response)) throw new Error("response changed");
			return undefined;
		}
		const result = leaderCountJobFinish(
			job.leader.state,
			job.leader.reportId,
			response,
		);
		const bucket = this.bucket(job.leader.time);
		if ("outputShare" in result) {
			if (bucket.collected || this.reports.has(job.leader.reportId.toHex()))
				throw new Error("report cannot be committed");
			this.reports.add(job.leader.reportId.toHex());
			add(bucket, result.outputShare);
		}
		bucket.pending--;
		job.response = response.slice();
		return "outputShare" in result ? result.outputShare : undefined;
	}

	collect(time: bigint): Uint8Array {
		const bucket = this.bucket(time);
		if (bucket.collected || bucket.pending)
			throw new Error("bucket unavailable");
		bucket.collected = true;
		const share = new Uint8Array(8);
		new DataView(share.buffer).setBigUint64(0, bucket.sum, true);
		return share;
	}
}

function same(a: Uint8Array, b: Uint8Array): boolean {
	return a.length === b.length && a.every((byte, i) => byte === b[i]);
}

function add(bucket: { sum: bigint; count: number }, share: Uint8Array): void {
	if (share.length !== 8) throw new Error("invalid output share");
	const value = new DataView(share.buffer, share.byteOffset, 8).getBigUint64(
		0,
		true,
	);
	if (value >= P) throw new Error("non-canonical output share");
	bucket.sum = (bucket.sum + value) % P;
	bucket.count++;
}

const rawKey = Uint8Array.fromHex(hpkeVector.skRm);
const verifyKey = new Uint8Array(32);

it("resumes interrupted jobs and commits each share once", async () => {
	const client = new DAPClient(task, {
		hpke,
		random: deterministicRandom(),
		clock: () => 179999,
	});
	const report = decodeReport(encodeReport(await client.prepareReport(1)));
	const leaderKey = await prepareAggregatorKey({
		configId: 7,
		privateKey: rawKey,
	});
	const helperKey = await prepareAggregatorKey({
		configId: 8,
		privateKey: rawKey,
	});
	const leaderStore = new MemoryStore();
	const helperStore = new MemoryStore();
	const leader = leaderStore.saveLeader(
		"job-1",
		await leaderCountJobInit(task, report, leaderKey, 0, verifyKey),
	);
	expect(() => leaderStore.collect(leader.time)).toThrow();
	const helperResult = await helperCountJobInit(
		task,
		leader.request,
		helperKey,
		0,
		verifyKey,
	);
	const helperResponse = helperStore.commitHelper(
		"job-1",
		leader.request,
		helperResult,
	);
	// The response was lost after Helper committed. Both roles restart from saved bytes.
	expect(helperStore.loadHelper("job-1", leader.request)).toEqual(
		helperResponse,
	);
	expect(helperStore.bucket(leader.time).count).toBe(1);
	expect(leaderStore.loadLeader("job-1")).toEqual(leader);
	expect(leaderStore.saveLeader("job-1", leader)).toEqual(leader);
	const leaderShare = leaderStore.commitLeader("job-1", helperResponse);
	expect(leaderStore.commitLeader("job-1", helperResponse)).toBeUndefined();
	expect(leaderStore.bucket(leader.time).count).toBe(1);
	expect(
		unshardCount([
			leaderStore.collect(leader.time),
			helperStore.collect(leader.time),
		]),
	).toBe(1n);
	expect(leaderShare).toBeDefined();
	const changed = leader.request.slice();
	changed[0] ^= 1;
	expect(() =>
		helperStore.commitHelper("job-1", changed, helperResult),
	).toThrow("job identity conflict");
	const replay = helperStore.commitHelper(
		"job-2",
		leader.request,
		helperResult,
	);
	expect(leaderCountJobFinish(leader.state, leader.reportId, replay)).toEqual({
		reportError: 2,
	});
	const second = decodeReport(encodeReport(await client.prepareReport(1)));
	const later = await leaderCountJobInit(task, second, leaderKey, 0, verifyKey);
	const afterCollection = helperStore.commitHelper(
		"job-3",
		later.request,
		await helperCountJobInit(task, later.request, helperKey, 0, verifyKey),
	);
	expect(
		leaderCountJobFinish(later.state, later.reportId, afterCollection),
	).toEqual({ reportError: 1 });
});

it("serializes competing jobs for the same report", async () => {
	const client = new DAPClient(task, { hpke, clock: () => 179999 });
	const report = decodeReport(encodeReport(await client.prepareReport(1)));
	const leaderKey = await prepareAggregatorKey({
		configId: 7,
		privateKey: rawKey,
	});
	const helperKey = await prepareAggregatorKey({
		configId: 8,
		privateKey: rawKey,
	});
	const leader = await leaderCountJobInit(
		task,
		report,
		leaderKey,
		0,
		verifyKey,
	);
	const store = new MemoryStore();
	const candidates = await Promise.all([
		helperCountJobInit(task, leader.request, helperKey, 0, verifyKey),
		helperCountJobInit(task, leader.request, helperKey, 0, verifyKey),
	]);
	const first = store.commitHelper("a", leader.request, candidates[0]!);
	const second = store.commitHelper("b", leader.request, candidates[1]!);
	expect(
		leaderCountJobFinish(leader.state, leader.reportId, first),
	).toHaveProperty("outputShare");
	expect(leaderCountJobFinish(leader.state, leader.reportId, second)).toEqual({
		reportError: 2,
	});
	expect(store.bucket(leader.time).count).toBe(1);
});
