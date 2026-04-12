const wasmModuleUrl = new URL("./dist/tyr_crypto_wasm.mjs", import.meta.url);

function toUint8Array(value) {
  if (value instanceof Uint8Array) return value;
  if (value instanceof ArrayBuffer) return new Uint8Array(value);
  if (ArrayBuffer.isView(value)) {
    return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  }
  if (Array.isArray(value)) return Uint8Array.from(value);
  throw new TypeError("Expected a Uint8Array-compatible value.");
}

function bytesToBase64(value) {
  const bytes = toUint8Array(value);
  if (typeof Buffer !== "undefined") {
    return Buffer.from(bytes).toString("base64");
  }
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function base64ToBytes(value) {
  if (typeof Buffer !== "undefined") {
    return new Uint8Array(Buffer.from(value, "base64"));
  }
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  let i = 0;
  while (i < binary.length) {
    bytes[i] = binary.charCodeAt(i);
    i += 1;
  }
  return bytes;
}

function callJson(module, symbol, payload) {
  const raw = payload === undefined
    ? module.ccall(symbol, "string", [], [])
    : module.ccall(symbol, "string", ["string"], [payload]);
  const parsed = JSON.parse(raw);
  if (!parsed.ok) {
    throw new Error(parsed.error || `Tyr wasm call failed for ${symbol}.`);
  }
  return parsed;
}

function encodeBasicCipherRequest(request, fieldName) {
  return JSON.stringify({
    algo: request.algo,
    key: bytesToBase64(request.key),
    nonce: bytesToBase64(request.nonce),
    [fieldName]: bytesToBase64(request[fieldName]),
  });
}

function encodeHashRequest(request) {
  return JSON.stringify({
    input: bytesToBase64(request.input),
    outLength: request.outLength ?? 0,
  });
}

function encodeKeyedHashRequest(request) {
  return JSON.stringify({
    key: bytesToBase64(request.key),
    input: bytesToBase64(request.input),
    outLength: request.outLength ?? 0,
  });
}

function resolveLocateFile(moduleOptions) {
  if (typeof moduleOptions.locateFile === "function") {
    return moduleOptions.locateFile;
  }
  return (path) => new URL(path, wasmModuleUrl).href;
}

class TyrBasicBinding {
  constructor(module) {
    this.module = module;
  }

  encrypt(request) {
    const response = callJson(
      this.module,
      "tyr_wasm_basic_encrypt_json",
      encodeBasicCipherRequest(request, "message"),
    );
    return {
      algo: response.algo,
      payload: base64ToBytes(response.payload),
    };
  }

  decrypt(request) {
    const response = callJson(
      this.module,
      "tyr_wasm_basic_decrypt_json",
      encodeBasicCipherRequest(request, "payload"),
    );
    return {
      algo: response.algo,
      payload: base64ToBytes(response.payload),
    };
  }

  blake3Hash(request) {
    const response = callJson(
      this.module,
      "tyr_wasm_blake3_hash_json",
      encodeHashRequest(request),
    );
    return base64ToBytes(response.bytes);
  }

  blake3KeyedHash(request) {
    const response = callJson(
      this.module,
      "tyr_wasm_blake3_keyed_hash_json",
      encodeKeyedHashRequest(request),
    );
    return base64ToBytes(response.bytes);
  }

  gimliHash(request) {
    const response = callJson(
      this.module,
      "tyr_wasm_gimli_hash_json",
      encodeHashRequest(request),
    );
    return base64ToBytes(response.bytes);
  }

  sha3Hash(request) {
    const response = callJson(
      this.module,
      "tyr_wasm_sha3_hash_json",
      encodeHashRequest(request),
    );
    return base64ToBytes(response.bytes);
  }
}

export class TyrCryptoBinding {
  constructor(module) {
    this.module = module;
    this.basic = new TyrBasicBinding(module);
  }

  abiVersion() {
    return this.module.ccall("tyr_wasm_abi_version", "number", [], []);
  }

  capabilities() {
    return callJson(this.module, "tyr_wasm_capabilities_json");
  }
}

export async function loadTyrCrypto(moduleOptions = {}) {
  const factoryModule = await import(wasmModuleUrl.href);
  const moduleFactory = factoryModule.default;
  const module = await moduleFactory({
    ...moduleOptions,
    locateFile: resolveLocateFile(moduleOptions),
  });
  return new TyrCryptoBinding(module);
}
