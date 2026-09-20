import { HpkeConfigList, prio3Count, Task } from "../src/index.js";
import { encodeHpkeConfigList } from "../src/messages.js";
import vector from "./vectors/hpke-rfc9180-a1.json";

export const hex = (value: string) => Uint8Array.fromHex(value);
export const text = (value: string) => new TextEncoder().encode(value);
export const taskOptions = {
	id: "8BY0RzZMzxvA46_8ymhzycOB9krN-QIGYvg_RsByGec",
	info: "p",
	leader: "https://l/",
	helper: "https://h/",
	timePrecision: 60,
	minBatchSize: 100,
	batchMode: "time-interval" as const,
	vdaf: prio3Count(),
};
export const task = Task.create(taskOptions);

// Hand-derived from DAP 19 Section 4.2. Not a published vector.
export const taskWire = hex(
	[
		"0170", // task_info
		"000a68747470733a2f2f6c2f", // leader
		"000a68747470733a2f2f682f", // helper
		"000000000000003c", // time_precision
		"0000000000000064", // min_batch_size
		"01",
		"0000", // time-interval, empty batch config
		"00000001",
		"0000",
		"0000", // Prio3Count, empty config/extensions
	].join(""),
);

export const config = {
	id: 7,
	kemId: 32,
	kdfId: 1,
	aeadId: 1,
	publicKey: hex(vector.pkRm),
};
export const hpke = {
	leader: HpkeConfigList.parse(encodeHpkeConfigList([config])),
	helper: HpkeConfigList.parse(encodeHpkeConfigList([{ ...config, id: 8 }])),
};

export function deterministicRandom() {
	let next = 0;
	return (length: number) => Uint8Array.from({ length }, () => next++ & 255);
}
