import {
	AEAD_AES_128_GCM,
	CipherSuite,
	KDF_HKDF_SHA256,
	KEM_DHKEM_X25519_HKDF_SHA256,
} from "hpke";
import { bytes } from "./binary.js";
import { DAPError } from "./errors.js";
import { decodeHpkeConfigList, type HpkeConfig } from "./messages.js";

/** Return exactly length fresh random bytes. Supply a deterministic source only in tests. */
export type RandomSource = (length: number) => Uint8Array;
export const secureRandom: RandomSource = (length) =>
	crypto.getRandomValues(new Uint8Array(length));

export function randomBytes(source: RandomSource, length: number): Uint8Array {
	return bytes(source(length), length).slice();
}

export function createSuite(random?: RandomSource): CipherSuite<CryptoKey> {
	const factory = random
		? () => {
				const kem = KEM_DHKEM_X25519_HKDF_SHA256();
				return {
					...kem,
					async GenerateKeyPair(extractable: boolean) {
						const seed = randomBytes(random, 32);
						try {
							return await kem.DeriveKeyPair(seed, extractable);
						} finally {
							seed.fill(0);
						}
					},
				};
			}
		: KEM_DHKEM_X25519_HKDF_SHA256;
	return new CipherSuite(factory, KDF_HKDF_SHA256, AEAD_AES_128_GCM);
}

/** Supply the recipient public key on runtimes without subtle.getPublicKey(). */
export async function prepareRecipientKey(
	privateBytes: Uint8Array,
): Promise<CryptoKeyPair> {
	const suite = createSuite();
	const secret = Uint8Array.from(bytes(privateBytes, 32));
	try {
		const temporary = await suite.DeserializePrivateKey(secret, true);
		const jwk = await crypto.subtle.exportKey("jwk", temporary);
		if (jwk.kty !== "OKP" || jwk.crv !== "X25519" || !jwk.x)
			throw new DAPError("InvalidHpkeConfig", "Invalid X25519 private key");
		const publicKey = await suite.DeserializePublicKey(
			bytes(
				Uint8Array.from(
					atob(jwk.x.replaceAll("-", "+").replaceAll("_", "/")),
					(char) => char.charCodeAt(0),
				),
				32,
			),
		);
		const privateKey = await suite.DeserializePrivateKey(secret);
		return { privateKey, publicKey };
	} finally {
		secret.fill(0);
	}
}

export class HpkeConfigList {
	#encoded: Uint8Array;
	private constructor(encoded: Uint8Array) {
		decodeHpkeConfigList(encoded);
		this.#encoded = encoded.slice();
		Object.freeze(this);
	}
	static parse(encoded: Uint8Array): HpkeConfigList {
		return new HpkeConfigList(encoded);
	}
	get configs(): readonly HpkeConfig[] {
		return decodeHpkeConfigList(this.#encoded);
	}
	encode(): Uint8Array {
		return this.#encoded.slice();
	}
}

export interface AggregatorHpkeConfigs {
	readonly leader: HpkeConfigList;
	readonly helper: HpkeConfigList;
}

export function selectConfig(list: HpkeConfigList): HpkeConfig {
	if (!(list instanceof HpkeConfigList))
		throw new DAPError("InvalidHpkeConfig", "Expected an HPKE config list");
	const config = list.configs.find(
		(config) =>
			config.kemId === 0x20 && config.kdfId === 1 && config.aeadId === 1,
	);
	if (!config)
		throw new DAPError(
			"UnsupportedCipherSuite",
			"No supported HPKE suite in the config list",
		);
	if (config.publicKey.length !== 32)
		throw new DAPError("InvalidHpkeConfig", "Invalid X25519 public key length");
	return config;
}
