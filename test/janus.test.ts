import { expect, it } from "vitest";
import { execute, fetchHpkeConfigs } from "../src/fetch.js";
import { DAPClient, prio3Count, Task } from "../src/index.js";

const enabled = process.env.JANUS_INTEROP === "1";
const leader = "http://leader:8080/";
const helper = "http://helper:8080/";

async function localFetch(input: RequestInfo | URL, init?: RequestInit) {
	const request = new Request(input, init);
	const url = new URL(request.url);
	const port = url.hostname === "leader" ? "9001" : "9002";
	url.hostname = "127.0.0.1";
	url.port = port;
	return fetch(new Request(url, request));
}

async function post(port: number, path: string, body?: unknown) {
	const response = await fetch(`http://127.0.0.1:${port}${path}`, {
		method: "POST",
		headers: body ? { "content-type": "application/json" } : undefined,
		body: body ? JSON.stringify(body) : undefined,
	});
	if (!response.ok) throw new Error(`Janus returned HTTP ${response.status}`);
	return response.json();
}

it.skipIf(!enabled)(
	"uploads a DAP 18 count report to Janus",
	async () => {
		for (const port of [9001, 9002]) {
			for (let attempt = 0; ; attempt++) {
				try {
					await post(port, "/internal/test/ready");
					break;
				} catch (error) {
					if (attempt === 59) throw error;
					await new Promise((resolve) => setTimeout(resolve, 1_000));
				}
			}
		}

		const task = Task.create({
			id: crypto.getRandomValues(new Uint8Array(32)).toBase64({
				alphabet: "base64url",
				omitPadding: true,
			}),
			info: "task-info",
			leader,
			helper,
			timePrecision: 60,
			minBatchSize: 1,
			batchMode: "time-interval",
			vdaf: prio3Count(),
			testOnly: { dapVersion: 18, allowInsecureHttp: true },
		});
		const hpke = await fetchHpkeConfigs(task, { fetch: localFetch });
		const collectorConfig = hpke.leader.encode().slice(2).toBase64({
			alphabet: "base64url",
			omitPadding: true,
		});
		const common = {
			task_id: task.id,
			leader,
			helper,
			vdaf: { type: "Prio3Count" },
			leader_authentication_token: "leader-token",
			vdaf_verify_key: new Uint8Array(32).toBase64({
				alphabet: "base64url",
				omitPadding: true,
			}),
			batch_mode: 1,
			min_batch_size: 1,
			time_precision: 60,
			collector_hpke_config: collectorConfig,
			task_start: null,
			task_end: null,
		};
		for (const [port, role] of [
			[9001, "leader"],
			[9002, "helper"],
		] as const) {
			const result = (await post(port, "/internal/test/add_task", {
				...common,
				role,
				collector_authentication_token:
					role === "leader" ? "collector-token" : null,
			})) as { status: string; error?: string };
			expect(result, result.error).toMatchObject({ status: "success" });
		}

		const client = new DAPClient(task, { hpke });
		const result = await execute(
			client.prepareUpload([await client.prepareReport(1)]),
			{ fetch: localFetch },
		);
		expect(result.ok).toBe(true);
	},
	90_000,
);
