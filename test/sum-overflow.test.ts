import { expect, it } from "vitest";
import { createSuite } from "../src/hpke.js";
import {
	Client,
	Collector,
	Helper,
	Leader,
	prio3Sum,
	Task,
} from "../src/index.js";

it("rejects a wrapped Sum after both aggregators verify the reports", async () => {
	const suite = createSuite();
	async function key(id: number) {
		const pair = await suite.GenerateKeyPair(true);
		return {
			privateKey: await suite.SerializePrivateKey(pair.privateKey),
			config: {
				id,
				kemId: 32,
				kdfId: 1,
				aeadId: 1,
				publicKey: await suite.SerializePublicKey(pair.publicKey),
			},
		};
	}
	const [l, h, c] = await Promise.all([key(1), key(2), key(3)]);
	const max = 18446744069414584320n;
	const time = 1800000000000;
	const task = Task.create({
		id: "8BY0RzZMzxvA46_8ymhzycOB9krN-QIGYvg_RsByGec",
		leader: "https://leader.example/",
		helper: "https://helper.example/",
		timePrecision: 60,
		minBatchSize: 2,
		batchMode: "time-interval",
		vdaf: prio3Sum(max),
	});
	const common = {
		verifyKeys: [{ id: 0, key: crypto.getRandomValues(new Uint8Array(32)) }],
		collector: c.config,
		clock: () => time,
	};
	const leader = await Leader.create(task, {
		...common,
		hpkeKeys: [{ configId: 1, privateKey: l.privateKey }],
	});
	const helper = await Helper.create(task, {
		...common,
		hpkeKeys: [{ configId: 2, privateKey: h.privateKey }],
	});
	const client = await Client.create(task, {
		hpke: { leader: leader.hpkeConfigs, helper: helper.hpkeConfigs },
		clock: () => time,
	});
	const reports = await Promise.all([
		client.prepareReport(max),
		client.prepareReport(max),
	]);
	const upload = client.prepareUpload(reports);
	const incoming = leader.upload(
		new Uint8Array(await upload.request.arrayBuffer()),
	);
	const job = await leader.prepare(incoming.reports.map((r) => r.report));
	const verified = await helper.verify(job.request!);
	let hb: Uint8Array<ArrayBuffer> | undefined,
		lb: Uint8Array<ArrayBuffer> | undefined;
	for (const r of verified.reports) {
		if (!r.outputShare) throw new Error(r.error);
		hb = helper.addToBucket(hb, r);
	}
	for (const r of leader.finish(job.state, verified.seal())) {
		if (!r.outputShare) throw new Error(r.error);
		lb = leader.addToBucket(lb, r);
	}
	const collector = await Collector.create(task, {
		configId: 3,
		privateKey: c.privateKey,
	});
	const query = collector.prepare({ start: time, end: time + 60000 });
	const collection = leader.collection(
		new Uint8Array(await query.request.arrayBuffer()),
	);
	const helperJob = helper.aggregateShare(
		collection.aggregateShareRequest(lb!),
	);
	const body = await collection.finish(lb!, await helperJob.finish(hb!));
	await expect(
		query.process(
			new Response(body, {
				headers: {
					"content-type": "application/ppm-dap;message=collection-job-resp",
					location: "https://leader.example/collection/1",
				},
			}),
		),
	).rejects.toThrow("Invalid aggregate share");
});
