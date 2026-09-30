import {
	Client,
	type ClientOptions,
	type CollectionProgress,
	type PreparedReport,
	type Prio3Histogram,
	prio3Count,
	prio3Histogram,
	prio3Sum,
	Task,
} from "../src/index.js";

// Compile-only checks for the public measurement type and opaque reports.
export async function check(options: ClientOptions) {
	const task = Task.create({
		id: "8BY0RzZMzxvA46_8ymhzycOB9krN-QIGYvg_RsByGec",
		leader: "https://l/",
		helper: "https://h/",
		timePrecision: 60,
		minBatchSize: 100,
		batchMode: "time-interval",
		vdaf: prio3Count(),
	});
	const client = await Client.create(task, options);
	await client.prepareReport(1);
	// @ts-expect-error Count measurements are 0 or 1.
	await client.prepareReport(2);
	// @ts-expect-error Count measurements are numbers.
	await client.prepareReport(1n);
	// @ts-expect-error Count measurements are not strings.
	await client.prepareReport("1");
	const decoded = Task.decode({
		id: task.id,
		configuration: task.encodeConfiguration(),
	}).expect(prio3Count());
	const narrowed = await Client.create(decoded, options);
	const sum = await Client.create(
		Task.create({
			id: task.id,
			leader: task.leader,
			helper: task.helper,
			timePrecision: 60,
			minBatchSize: 100,
			batchMode: "time-interval",
			vdaf: prio3Sum(1337),
		}),
		options,
	);
	await sum.prepareReport(42n);
	await sum.prepareReport(42);
	const histogram = await Client.create(
		Task.create({
			id: task.id,
			leader: task.leader,
			helper: task.helper,
			timePrecision: 60,
			minBatchSize: 100,
			batchMode: "time-interval",
			vdaf: prio3Histogram(4, 2),
		}),
		options,
	);
	await histogram.prepareReport(2);
	// @ts-expect-error Histogram buckets are numbers.
	await histogram.prepareReport(2n);
	// @ts-expect-error Sum measurements are integers, not strings.
	await sum.prepareReport("42");
	// @ts-expect-error expect() restores the measurement type.
	await narrowed.prepareReport(true);
	const progress = {} as CollectionProgress<Prio3Histogram>;
	if (progress.status === "complete") {
		const buckets: readonly bigint[] = progress.value;
		// @ts-expect-error Histogram results are bucket arrays.
		const total: bigint = progress.value;
		void buckets;
		void total;
	}
	// @ts-expect-error Reports must be prepared by a client.
	const report: PreparedReport = { id: "anything", time: 0 };
	return report;
}
