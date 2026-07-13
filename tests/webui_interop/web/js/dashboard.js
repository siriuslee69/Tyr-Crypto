import { loadTyrCrypto } from "../wasm/tyr_crypto.js";

const $ = (selector, root = document) => root.querySelector(selector);
const textEncoder = new TextEncoder();
const algorithms = [
  { kind: "sym", algo: "xchacha20", title: "XChaCha20", family: "stream / 24 byte nonce", glyph: "<>" },
  { kind: "sym", algo: "chacha20", title: "ChaCha20", family: "stream / 12 byte nonce", glyph: "//" },
  { kind: "sym", algo: "aesCtr", title: "AES-256-CTR", family: "stream / 16 byte nonce", glyph: "[]" },
  { kind: "sym", algo: "gimliStream", title: "Gimli Stream", family: "sponge stream / 24 byte nonce", glyph: "{}" },
  { kind: "kem", algo: "x25519", title: "X25519", family: "elliptic key exchange", glyph: "()" },
  { kind: "kem", algo: "kyber768", title: "Kyber-768", family: "post-quantum KEM", glyph: "<>" },
  { kind: "kem", algo: "kyber1024", title: "Kyber-1024", family: "post-quantum KEM", glyph: "##" },
];
const messages = ["amber signal", "quiet comet", "north star relay"];
const tests = {
  all: { label: "all tests", algorithms },
  transport: { label: "transport", algorithms: [] },
  sym: { label: "cipher suite", algorithms: algorithms.filter(item => item.kind === "sym") },
  kem: { label: "KEM suite", algorithms: algorithms.filter(item => item.kind === "kem") },
};
let binding;
let passCount = 0;
let selectedTest = "all";
let running = false;

algorithms.forEach(algorithm => {
  tests[algorithm.algo] = { label: algorithm.title, algorithms: [algorithm] };
});

function bytes(size) { const out = new Uint8Array(size); crypto.getRandomValues(out); return out; }
function equal(a, b) { return a.length === b.length && a.every((v, i) => v === b[i]); }
function preview(value) { const bytesValue = typeof value === "string" ? textEncoder.encode(value) : value; return [...bytesValue.slice(0, 8)].map(v => v.toString(16).padStart(2, "0")).join("") + (bytesValue.length > 8 ? "..." : ""); }
function callNative(name, value) {
  const globalBinding = window[name];
  const webuiBinding = window.webui?.[name];
  if (typeof globalBinding === "function") return globalBinding(value);
  if (typeof webuiBinding === "function") return webuiBinding.call(window.webui, value);
  if (typeof window.webui?.call === "function") return window.webui.call(name, value);
  throw new Error(`WebUI binding is unavailable: ${name}`);
}
function backend(request) {
  return Promise.resolve(callNative("interop", JSON.stringify(request))).then(JSON.parse).then(response => {
    if (!response.ok) throw new Error(response.error || "native crypto request failed");
    return response;
  });
}
function decode(base64) { const raw = atob(base64); return Uint8Array.from(raw, char => char.charCodeAt(0)); }
function encode(value) { let raw = ""; for (const byte of value) raw += String.fromCharCode(byte); return btoa(raw); }
function seed(label, size = 32) { const out = new Uint8Array(size); for (let i = 0; i < size; i += 1) out[i] = (label.charCodeAt(i % label.length) + i * 29) & 255; return out; }

function createBubbles() {
  const host = $("[data-bubbles]"); const template = $("[data-bubble-template]");
  algorithms.forEach((algorithm) => {
    const element = template.content.firstElementChild.cloneNode(true);
    element.dataset.algo = algorithm.algo;
    $(".glyph", element).textContent = algorithm.glyph;
    $(".family", element).textContent = algorithm.family;
    $("h2", element).textContent = algorithm.title;
    host.append(element);
  });
  $("[data-algo-count]").textContent = String(algorithms.length);
}
function selectedAlgorithms() { return tests[selectedTest].algorithms; }
function selectTest(name) {
  if (running || !tests[name]) return;
  selectedTest = name;
  document.querySelectorAll("[data-test]").forEach(button => {
    button.classList.toggle("is-active", button.dataset.test === name);
  });
  document.querySelectorAll("[data-algo]").forEach(bubble => {
    const active = selectedAlgorithms().some(item => item.algo === bubble.dataset.algo);
    bubble.classList.toggle("is-muted", !active);
  });
  $("[data-selected-label]").textContent = tests[name].label.toUpperCase();
  $("[data-run-label]").textContent = tests[name].label;
  $("[data-algo-count]").textContent = String(selectedAlgorithms().length);
  $("[data-state]").textContent = `${tests[name].label} selected`;
}
function setControlsDisabled(disabled) {
  $("[data-run]").disabled = disabled;
  document.querySelectorAll("[data-test]").forEach(button => { button.disabled = disabled; });
}
function updateBubble(algo, state, details = {}) {
  const bubble = document.querySelector(`[data-algo="${algo}"]`);
  bubble.className = `bubble glass is-${state}`;
  $(".badge", bubble).textContent = state.toUpperCase();
  if (details.message) $(".message", bubble).textContent = details.message;
  if (details.decipher) $(".decipher", bubble).textContent = details.decipher;
  if (details.key) $(".key", bubble).textContent = details.key;
  if (details.result) $(".result", bubble).textContent = details.result;
  if (details.duration) $(".duration", bubble).textContent = `${details.duration.toFixed(1)} ms`;
}

async function runSymmetric(algorithm) {
  const nonceBytes = binding.capabilities().basicCiphers.find(cap => cap.name === algorithm.algo).nonceBytes;
  const key = seed(`${algorithm.algo}-key`); const nonce = seed(`${algorithm.algo}-nonce`, nonceBytes);
  let last = ""; const start = performance.now();
  for (const message of messages) {
    const plain = textEncoder.encode(message);
    const browserCipher = binding.basic.encrypt({ algo: algorithm.algo, key, nonce, message: plain }).payload;
    const nativeOpen = await backend({ action: "symDecrypt", algo: algorithm.algo, key: encode(key), nonce: encode(nonce), payload: encode(browserCipher) });
    const browserPlain = decode(nativeOpen.bytes);
    const nativeCipher = await backend({ action: "symEncrypt", algo: algorithm.algo, key: encode(key), nonce: encode(nonce), message: encode(plain) });
    const nativePayload = decode(nativeCipher.bytes);
    const browserOpen = binding.basic.decrypt({ algo: algorithm.algo, key, nonce, payload: nativePayload }).payload;
    if (!equal(plain, browserPlain)) {
      throw new Error(`browser encrypt -> native decrypt mismatch (${preview(browserPlain)})`);
    }
    if (!equal(plain, browserOpen)) {
      throw new Error(`native encrypt -> browser decrypt mismatch (${preview(browserOpen)})`);
    }
    last = message;
  }
  return { message: last, decipher: last, key: preview(key), duration: performance.now() - start, exchanges: messages.length * 2 };
}

async function runKem(algorithm) {
  const start = performance.now(); const keySeed = seed(`${algorithm.algo}-keypair`); const encSeed = seed(`${algorithm.algo}-encaps`);
  const keypair = binding.basic.kemKeypair({ algo: algorithm.algo, seed: keySeed });
  const browserCipher = binding.basic.kemEncaps({ algo: algorithm.algo, receiverPublicKey: keypair.publicKey, seed: encSeed });
  const nativeOpen = await backend({ action: "kemDecaps", algo: algorithm.algo, secretKey: encode(keypair.secretKey), payload: encode(browserCipher.ciphertext) });
  const nativeCipher = await backend({ action: "kemEncaps", algo: algorithm.algo, publicKey: encode(keypair.publicKey), seed: encode(encSeed) });
  const browserOpen = binding.basic.kemDecaps({ algo: algorithm.algo, receiverSecretKey: keypair.secretKey, ciphertext: decode(nativeCipher.ciphertext) });
  if (!equal(browserCipher.sharedSecret, decode(nativeOpen.bytes))) {
    throw new Error(`browser encaps -> native decaps mismatch (${preview(browserCipher.sharedSecret)} / ${preview(decode(nativeOpen.bytes))})`);
  }
  if (!equal(browserOpen.sharedSecret, decode(nativeCipher.sharedSecret))) {
    throw new Error(`native encaps -> browser decaps mismatch (${preview(browserOpen.sharedSecret)} / ${preview(decode(nativeCipher.sharedSecret))})`);
  }
  return { message: "KEM ciphertext accepted", decipher: "shared secret matched", key: preview(browserOpen.sharedSecret), duration: performance.now() - start, exchanges: 2 };
}

async function runAlgorithm(algorithm) {
  updateBubble(algorithm.algo, "running", { result: "browser <-> native in flight" });
  try {
    const result = algorithm.kind === "sym" ? await runSymmetric(algorithm) : await runKem(algorithm);
    passCount += result.exchanges; $("[data-pass-count]").textContent = String(passCount);
    updateBubble(algorithm.algo, "pass", { ...result, result: "both directions correct" });
  } catch (error) {
    updateBubble(algorithm.algo, "fail", { result: error.message, decipher: "check failure" });
    throw error;
  }
}

async function runTransport() {
  const probeBytes = seed("webui-transport-test", 4096);
  const response = await backend({ action: "echo", algo: "transport", message: encode(probeBytes) });
  if (!equal(probeBytes, decode(response.bytes))) throw new Error("4 KiB WebUI byte transport mismatch");
  return 1;
}

async function runSelection() {
  if (running) return;
  running = true;
  passCount = 0; $("[data-pass-count]").textContent = "0"; const start = performance.now();
  const activeAlgorithms = selectedAlgorithms();
  let failed = 0;
  let errors = [];
  $("[data-state]").textContent = `${tests[selectedTest].label} running: browser WASM and native basic_api`;
  setControlsDisabled(true);
  if (selectedTest === "transport") {
    try { passCount = await runTransport(); }
    catch (error) { failed = 1; errors = [`transport: ${error.message}`]; }
  } else {
    const results = await Promise.allSettled(activeAlgorithms.map(runAlgorithm));
    failed = results.filter(result => result.status === "rejected").length;
    errors = results.map((result, index) => result.status === "rejected"
      ? `${activeAlgorithms[index].algo}: ${result.reason?.message || result.reason}` : "").filter(Boolean);
  }
  $("[data-pass-count]").textContent = String(passCount);
  $("[data-state]").textContent = failed ? `${tests[selectedTest].label}: ${failed} failed` : `${tests[selectedTest].label} verified`;
  $("[data-timing]").textContent = `${(performance.now() - start).toFixed(1)} ms / ${passCount} exchanges / ${tests[selectedTest].label}`;
  running = false;
  setControlsDisabled(false);
  window.tyrInteropStatus = { complete: true, failed, exchanges: passCount };
  await callNative("interopComplete", `${failed}|${passCount}|${errors.join("; ")}`);
}

async function boot() {
  createBubbles();
  document.querySelectorAll("[data-test]").forEach(button => {
    button.addEventListener("click", () => selectTest(button.dataset.test));
  });
  $("[data-run]").addEventListener("click", runSelection);
  selectTest("all");
  try { binding = await loadTyrCrypto(); $("[data-state]").textContent = `WASM ABI ${binding.abiVersion()} online`; await runSelection(); }
  catch (error) {
    window.tyrInteropStatus = { complete: true, failed: 1, exchanges: 0, error: error.message };
    $("[data-state]").textContent = `startup failed: ${error.message}`;
    await callNative("interopComplete", `1|0|${error.stack || error.message}`);
  }
}

async function bootWhenWebUiReady() {
  let lastError;
  for (let attempt = 0; attempt < 100; attempt += 1) {
    try {
      const probeBytes = seed("webui-transport-probe", 4096);
      const probe = JSON.parse(await callNative("interop", JSON.stringify({
        action: "echo", algo: "transport", message: encode(probeBytes),
      })));
      if (!probe.ok || !equal(probeBytes, decode(probe.bytes))) {
        throw new Error("WebUI byte transport probe failed");
      }
      await boot();
      return;
    } catch (error) {
      lastError = error;
      await new Promise(resolve => setTimeout(resolve, 50));
    }
  }
  throw lastError || new Error("WebUI bindings did not become ready");
}

bootWhenWebUiReady();
