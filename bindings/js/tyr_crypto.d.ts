export type TyrBasicCipherAlgo =
  | "xchacha20"
  | "chacha20"
  | "aesCtr"
  | "gimliStream";

export type TyrKemAlgo = "x25519" | "kyber768" | "kyber1024";

export interface TyrBasicCapability {
  name: TyrBasicCipherAlgo;
  nonceBytes: number;
  notes: string;
}

export interface TyrCapabilities {
  ok: true;
  abiVersion: number;
  basicCiphers: TyrBasicCapability[];
}

export interface TyrBasicEncryptRequest {
  algo: TyrBasicCipherAlgo;
  key: Uint8Array;
  nonce: Uint8Array;
  message: Uint8Array;
}

export interface TyrBasicDecryptRequest {
  algo: TyrBasicCipherAlgo;
  key: Uint8Array;
  nonce: Uint8Array;
  payload: Uint8Array;
}

export interface TyrBasicCipherResponse {
  algo: TyrBasicCipherAlgo;
  payload: Uint8Array;
}

export interface TyrHashRequest {
  input: Uint8Array;
  outLength?: number;
}

export interface TyrKeyedHashRequest extends TyrHashRequest {
  key: Uint8Array;
}

export interface TyrKemKeypairRequest {
  algo: TyrKemAlgo;
  seed?: Uint8Array;
}

export interface TyrKemEncapsRequest {
  algo: TyrKemAlgo;
  receiverPublicKey: Uint8Array;
  seed?: Uint8Array;
}

export interface TyrKemDecapsRequest {
  algo: TyrKemAlgo;
  receiverSecretKey: Uint8Array;
  ciphertext: Uint8Array;
}

export interface TyrKemKeypairResponse {
  algo: TyrKemAlgo;
  publicKey: Uint8Array;
  secretKey: Uint8Array;
}

export interface TyrKemCipherResponse {
  algo: TyrKemAlgo;
  ciphertext: Uint8Array;
  sharedSecret: Uint8Array;
}

export interface TyrKemSecretResponse {
  algo: TyrKemAlgo;
  sharedSecret: Uint8Array;
}

export interface TyrModuleOptions {
  locateFile?: (path: string, prefix?: string) => string;
  [key: string]: unknown;
}

export class TyrBasicBinding {
  constructor(module: unknown);
  encrypt(request: TyrBasicEncryptRequest): TyrBasicCipherResponse;
  decrypt(request: TyrBasicDecryptRequest): TyrBasicCipherResponse;
  blake3Hash(request: TyrHashRequest): Uint8Array;
  blake3KeyedHash(request: TyrKeyedHashRequest): Uint8Array;
  gimliHash(request: TyrHashRequest): Uint8Array;
  sha3Hash(request: TyrHashRequest): Uint8Array;
  kemKeypair(request: TyrKemKeypairRequest): TyrKemKeypairResponse;
  kemEncaps(request: TyrKemEncapsRequest): TyrKemCipherResponse;
  kemDecaps(request: TyrKemDecapsRequest): TyrKemSecretResponse;
}

export class TyrCryptoBinding {
  constructor(module: unknown);
  abiVersion(): number;
  capabilities(): TyrCapabilities;
  basic: TyrBasicBinding;
}

export function loadTyrCrypto(moduleOptions?: TyrModuleOptions): Promise<TyrCryptoBinding>;
