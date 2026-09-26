import {
	DAPClient,
	type DAPClientOptions,
	type PreparedReport,
	prio3Count,
	prio3Histogram,
	prio3Sum,
	Task,
} from "../src/index.js";

// Compile-only checks for the public measurement type and opaque reports.
export async function check(options: DAPClientOptions) {
	const task = Task.create({
		id: "8BY0RzZMzxvA46_8ymhzycOB9krN-QIGYvg_RsByGec",
		leader: "https://l/",
		helper: "https://h/",
		timePrecision: 60,
		minBatchSize: 100,
		batchMode: "time-interval",
		vdaf: prio3Count(),
	});
	const client = new DAPClient(task, options);
	await client.prepareReport(1);
	await client.prepareReport(2); // Valid number type, rejected at runtime.
	// @ts-expect-error Count measurements are numbers.
	await client.prepareReport(1n);
	// @ts-expect-error Count measurements are not strings.
	await client.prepareReport("1");
	const decoded = Task.decode({
		id: task.id,
		configuration: task.encodeConfiguration(),
	}).expect(prio3Count());
	const narrowed = new DAPClient(decoded, options);
	const sum = new DAPClient(
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
	const histogram = new DAPClient(
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
	// @ts-expect-error Reports must be prepared by a client.
	const report: PreparedReport = { id: "anything", time: 0 };
	return report;
}
