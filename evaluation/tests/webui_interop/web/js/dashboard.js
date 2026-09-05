import { loadTyrCrypto } from "../wasm/tyr_crypto.js";

const $ = (selector, root = document) => root.querySelector(selector);
const textEncoder = new TextEncoder();
const interopAlgorithms = [
  { kind: "sym", algo: "xchacha20", title: "XChaCha20", family: "stream / 24 byte nonce", glyph: "<>" },
  { kind: "sym", algo: "chacha20", title: "ChaCha20", family: "stream / 12 byte nonce", glyph: "//" },
  { kind: "sym", algo: "aesCtr", title: "AES-256-CTR", family: "stream / 16 byte nonce", glyph: "[]" },
  { kind: "sym", algo: "gimliStream", title: "Gimli Stream", family: "sponge stream / 24 byte nonce", glyph: "{}" },
  { kind: "kem", algo: "x25519", title: "X25519", family: "elliptic key exchange", glyph: "()" },
  { kind: "kem", algo: "kyber768", title: "Kyber-768", family: "post-quantum KEM", glyph: "<>" },
  { kind: "kem", algo: "kyber1024", title: "Kyber-1024", family: "post-quantum KEM", glyph: "##" },
];
const messages = ["amber signal", "quiet comet", "north star relay"];
let binding;
let catalog = [];
let catalogInfo;
let selectedFilter = "all-tests";
let selectedFamily = "all";
let interopRunning = false;
let passCount = 0;
let currentPickerPath = "";
const jobStates = new Map();
let pollTimer;
let lastPollSummary = "";

function equal(a, b) { return a.length === b.length && a.every((value, index) => value === b[index]); }
function preview(value) { const bytesValue = typeof value === "string" ? textEncoder.encode(value) : value; return [...bytesValue.slice(0, 8)].map(value => value.toString(16).padStart(2, "0")).join("") + (bytesValue.length > 8 ? "..." : ""); }
function decode(base64) { const raw = atob(base64); return Uint8Array.from(raw, char => char.charCodeAt(0)); }
function encode(value) { let raw = ""; for (const byte of value) raw += String.fromCharCode(byte); return btoa(raw); }
function seed(label, size = 32) { const output = new Uint8Array(size); for (let index = 0; index < size; index += 1) output[index] = (label.charCodeAt(index % label.length) + index * 29) & 255; return output; }
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
    if (!response.ok) throw new Error(response.error || "native request failed");
    return response;
  });
}
function filterLabel() {
  const labels = {
    "all-tests": "all tests", functional: "functional", vectors: "vectors / KAT",
    edge: "edge cases", benchmark: "benchmarks", interop: "browser / WASM",
  };
  return labels[selectedFilter] || selectedFilter;
}
function entryMatches(entry) {
  const familyMatch = selectedFamily === "all" || entry.family === selectedFamily;
  if (!familyMatch || selectedFilter === "interop") return false;
  if (selectedFilter === "all-tests") return true;
  if (selectedFilter === "vectors") return entry.tags.includes("vectors") || entry.tags.includes("kat");
  return entry.tags.includes(selectedFilter);
}
function selectedEntries() { return catalog.filter(entryMatches); }
function setStatus(message) { $("[data-state]").textContent = message; }
function setPathState(message, failed = false) {
  const state = $("[data-path-state]");
  state.textContent = message;
  state.style.color = failed ? "var(--bad)" : "";
}
function createInteropBubbles() {
  const host = $("[data-bubbles]");
  const template = $("[data-bubble-template]");
  interopAlgorithms.forEach(algorithm => {
    const element = template.content.firstElementChild.cloneNode(true);
    element.dataset.algo = algorithm.algo;
    $(".glyph", element).textContent = algorithm.glyph;
    $(".family", element).textContent = algorithm.family;
    $("h2", element).textContent = algorithm.title;
    host.append(element);
  });
}
function updateInteropBubble(algo, state, details = {}) {
  const bubble = document.querySelector(`[data-algo="${algo}"]`);
  bubble.className = `bubble glass is-${state}`;
  $(".badge", bubble).textContent = state.toUpperCase();
  if (details.message) $(".message", bubble).textContent = details.message;
  if (details.decipher) $(".decipher", bubble).textContent = details.decipher;
  if (details.key) $(".key", bubble).textContent = details.key;
  if (details.result) $(".result", bubble).textContent = details.result;
  if (details.duration !== undefined) $(".duration", bubble).textContent = `${details.duration.toFixed(1)} ms`;
}
async function runSymmetric(algorithm) {
  const capability = binding.capabilities().basicCiphers.find(item => item.name === algorithm.algo);
  const key = seed(`${algorithm.algo}-key`);
  const nonce = seed(`${algorithm.algo}-nonce`, capability.nonceBytes);
  let last = "";
  const start = performance.now();
  for (const message of messages) {
    const plain = textEncoder.encode(message);
    const browserCipher = binding.basic.encrypt({ algo: algorithm.algo, key, nonce, message: plain }).payload;
    const nativeOpen = await backend({ action: "symDecrypt", algo: algorithm.algo, key: encode(key), nonce: encode(nonce), payload: encode(browserCipher) });
    const nativeCipher = await backend({ action: "symEncrypt", algo: algorithm.algo, key: encode(key), nonce: encode(nonce), message: encode(plain) });
    const browserOpen = binding.basic.decrypt({ algo: algorithm.algo, key, nonce, payload: decode(nativeCipher.bytes) }).payload;
    if (!equal(plain, decode(nativeOpen.bytes))) throw new Error("browser encrypt -> native decrypt mismatch");
    if (!equal(plain, browserOpen)) throw new Error("native encrypt -> browser decrypt mismatch");
    last = message;
  }
  return { message: last, decipher: last, key: preview(key), duration: performance.now() - start, exchanges: messages.length * 2 };
}
async function runKem(algorithm) {
  const start = performance.now();
  const keySeed = seed(`${algorithm.algo}-keypair`);
  const encSeed = seed(`${algorithm.algo}-encaps`);
  const keypair = binding.basic.kemKeypair({ algo: algorithm.algo, seed: keySeed });
  const browserCipher = binding.basic.kemEncaps({ algo: algorithm.algo, receiverPublicKey: keypair.publicKey, seed: encSeed });
  const nativeOpen = await backend({ action: "kemDecaps", algo: algorithm.algo, secretKey: encode(keypair.secretKey), payload: encode(browserCipher.ciphertext) });
  const nativeCipher = await backend({ action: "kemEncaps", algo: algorithm.algo, publicKey: encode(keypair.publicKey), seed: encode(encSeed) });
  const browserOpen = binding.basic.kemDecaps({ algo: algorithm.algo, receiverSecretKey: keypair.secretKey, ciphertext: decode(nativeCipher.ciphertext) });
  if (!equal(browserCipher.sharedSecret, decode(nativeOpen.bytes))) throw new Error("browser encaps -> native decaps mismatch");
  if (!equal(browserOpen.sharedSecret, decode(nativeCipher.sharedSecret))) throw new Error("native encaps -> browser decaps mismatch");
  return { message: "KEM ciphertext accepted", decipher: "shared secret matched", key: preview(browserOpen.sharedSecret), duration: performance.now() - start, exchanges: 2 };
}
async function runInteropAlgorithm(algorithm) {
  updateInteropBubble(algorithm.algo, "running", { result: "browser <-> native in flight" });
  try {
    const result = algorithm.kind === "sym" ? await runSymmetric(algorithm) : await runKem(algorithm);
    passCount += result.exchanges;
    $("[data-pass-count]").textContent = String(passCount);
    updateInteropBubble(algorithm.algo, "pass", { ...result, result: "both directions correct" });
    return result;
  } catch (error) {
    updateInteropBubble(algorithm.algo, "fail", { result: error.message, decipher: "check failure" });
    throw error;
  }
}
async function runInteropMatrix() {
  const start = performance.now();
  passCount = 0;
  setStatus("browser-WASM matrix running");
  const results = await Promise.allSettled(interopAlgorithms.map(runInteropAlgorithm));
  const failed = results.filter(result => result.status === "rejected").length;
  const errors = results.map((result, index) => result.status === "rejected" ? `${interopAlgorithms[index].algo}: ${result.reason?.message || result.reason}` : "").filter(Boolean);
  const duration = performance.now() - start;
  const summary = failed ? `${failed} browser-WASM paths failed` : "all browser-WASM paths verified";
  setStatus(summary);
  $("[data-timing]").textContent = `${duration.toFixed(1)} ms / ${passCount} exchanges / browser-WASM`;
  if (!catalogInfo.smokeMode) {
    await backend({ action: "recordInteropResult", algo: "interop", passed: failed === 0, durationMs: Math.round(duration), output: `${summary}\n${errors.join("\n")}` });
  }
  window.tyrInteropStatus = { complete: true, failed, exchanges: passCount };
  await callNative("interopComplete", `${failed}|${passCount}|${errors.join("; ")}`);
  return { failed, passed: passCount };
}

function createCatalogCards() {
  const host = $("[data-catalog]");
  const template = $("[data-catalog-template]");
  catalog.forEach(entry => {
    const card = template.content.firstElementChild.cloneNode(true);
    card.dataset.entryId = entry.id;
    card.dataset.family = entry.family;
    $(".card-family", card).textContent = entry.family;
    $("h2", card).textContent = entry.title;
    $(".card-source", card).textContent = entry.sources.join(" + ");
    entry.tags.forEach(tagName => {
      const tag = document.createElement("span");
      tag.className = `tag ${tagName}`;
      tag.textContent = tagName;
      $(".tag-row", card).append(tag);
    });
    $(".card-run", card).addEventListener("click", () => toggleCatalogJob(entry));
    card.querySelectorAll("[data-phase-tab]").forEach(tab => {
      tab.addEventListener("click", () => selectPhaseTab(card, tab.dataset.phaseTab));
    });
    host.append(card);
  });
}
function createFamilyButtons() {
  const host = $("[data-family-buttons]");
  const families = ["all", ...new Set(catalog.map(entry => entry.family))];
  families.forEach(family => {
    const button = document.createElement("button");
    button.className = `family-button${family === "all" ? " is-active" : ""}`;
    button.dataset.family = family;
    button.textContent = family;
    button.addEventListener("click", () => selectFamily(family));
    host.append(button);
  });
}
function selectPhaseTab(card, phase) {
  card.querySelectorAll("[data-phase-tab]").forEach(tab => tab.classList.toggle("is-active", tab.dataset.phaseTab === phase));
  card.querySelectorAll("[data-phase-panel]").forEach(panel => { panel.hidden = panel.dataset.phasePanel !== phase; });
}
function phaseResultText(phase) {
  const labels = {
    queued: `${phase.name} queued`, running: `${phase.name} compiling or running`,
    pass: `${phase.name} passed`, fail: `${phase.name} failed with exit ${phase.exitCode}`,
    stopped: `${phase.name} stopped`, blocked: `${phase.name} blocked by native failure`,
  };
  return labels[phase.status] || `${phase.name} not run`;
}
function updatePhase(card, phaseName, phase) {
  const tab = card.querySelector(`[data-phase-tab="${phaseName}"]`);
  const panel = card.querySelector(`[data-phase-panel="${phaseName}"]`);
  tab.className = `phase-tab is-${phase.status}${tab.classList.contains("is-active") ? " is-active" : ""}`;
  $(".card-result", panel).textContent = phaseResultText(phase);
  $(".card-duration", panel).textContent = phase.durationMs ? `${phase.durationMs} ms` : "-- ms";
  const log = $(".card-log", panel);
  if (phase.logPath) {
    log.hidden = false;
    log.textContent = phase.logPath.split("/").pop();
    log.title = phase.logPath;
  }
}
function updateCatalogCard(entry, state) {
  const card = document.querySelector(`[data-entry-id="${entry.id}"]`);
  const status = state.status || "idle";
  const active = ["queued", "running"].includes(status);
  card.className = `test-card glass is-${status}`;
  $(".badge", card).textContent = status.toUpperCase();
  $(".card-run", card).textContent = active ? "■" : "▶";
  $(".card-run", card).title = active ? "Stop this test job" : "Start this native then WASM test pair";
  updatePhase(card, "native", state.native || { name: "native", status: "queued" });
  updatePhase(card, "wasm", state.wasm || { name: "wasm", status: "queued" });
}
function refreshSelection() {
  const isInterop = selectedFilter === "interop";
  $("[data-catalog-head]").hidden = isInterop;
  $("[data-catalog]").hidden = isInterop;
  $("[data-interop-zone]").hidden = !isInterop;
  document.querySelectorAll("[data-filter]").forEach(button => button.classList.toggle("is-active", button.dataset.filter === selectedFilter));
  document.querySelectorAll("[data-family]").forEach(button => button.classList.toggle("is-active", button.dataset.family === selectedFamily));
  document.querySelectorAll("[data-entry-id]").forEach(card => {
    const entry = catalog.find(item => item.id === card.dataset.entryId);
    card.hidden = !entryMatches(entry);
  });
  const count = isInterop ? interopAlgorithms.length : selectedEntries().length;
  $("[data-algo-count]").textContent = String(count);
  $("[data-selected-label]").textContent = filterLabel().toUpperCase();
  $("[data-run-label]").textContent = filterLabel();
  setStatus(`${filterLabel()} selected`);
}
function selectFilter(filter) {
  selectedFilter = filter;
  selectedFamily = "all";
  refreshSelection();
}
function selectFamily(family) {
  if (selectedFilter === "interop") return;
  selectedFamily = family;
  refreshSelection();
}
function isJobActive(id) {
  return ["queued", "running"].includes(jobStates.get(id)?.status);
}
async function startCatalogJob(entry) {
  try {
    await backend({ action: "startCatalogJob", algo: "catalog", id: entry.id });
    const queued = { id: entry.id, status: "queued", native: { name: "native", status: "queued" }, wasm: { name: "wasm", status: "queued" } };
    jobStates.set(entry.id, queued);
    updateCatalogCard(entry, queued);
  } catch (error) {
    const failed = { id: entry.id, status: "fail", native: { name: "native", status: "fail", exitCode: 1 }, wasm: { name: "wasm", status: "blocked", exitCode: 1 } };
    jobStates.set(entry.id, failed);
    updateCatalogCard(entry, failed);
    setStatus(error.message);
  }
}
async function stopCatalogJob(entry) {
  await backend({ action: "stopCatalogJob", algo: "catalog", id: entry.id });
  setStatus(`stopping ${entry.title}`);
}
async function toggleCatalogJob(entry) {
  if (isJobActive(entry.id)) await stopCatalogJob(entry);
  else await startCatalogJob(entry);
}
async function startCatalogEntries(entries) {
  if (entries.length === 0) return;
  await Promise.all(entries.map(entry => isJobActive(entry.id) ? Promise.resolve() : startCatalogJob(entry)));
  setStatus(`${entries.length} paired native/WASM jobs launched`);
}
async function pollCatalogJobs() {
  if (catalogInfo?.smokeMode) return;
  try {
    const response = await backend({ action: "pollCatalogJobs", algo: "catalog" });
    let active = 0; let passed = 0; let failed = 0;
    response.jobs.forEach(state => {
      const prior = jobStates.get(state.id);
      const changed = JSON.stringify(prior) !== JSON.stringify(state);
      jobStates.set(state.id, state);
      const entry = catalog.find(item => item.id === state.id);
      if (changed && entry) updateCatalogCard(entry, state);
      if (["queued", "running"].includes(state.status)) active += 1;
      else if (state.status === "pass") passed += 1;
      else if (["fail", "stopped"].includes(state.status)) failed += 1;
    });
    const summary = `${active}|${passed}|${failed}`;
    if (summary !== lastPollSummary) {
      $("[data-stop-all]").disabled = active === 0;
      $("[data-pass-count]").textContent = String(passed);
      if (active > 0) setStatus(`${active} paired jobs running / navigation remains available`);
      $("[data-timing]").textContent = `${active} active / ${passed} passed / ${failed} failed or stopped`;
      lastPollSummary = summary;
    }
  } catch (error) {
    setStatus(`test spawner unavailable: ${error.message}`);
  }
}
async function stopAllCatalogJobs() {
  await backend({ action: "stopAllCatalogJobs", algo: "catalog" });
  setStatus("stopping all test jobs");
}
async function runSelection() {
  if (selectedFilter === "interop") {
    if (interopRunning) return;
    interopRunning = true;
    try {
      await runInteropMatrix();
    } finally {
      interopRunning = false;
    }
    return;
  }
  await startCatalogEntries(selectedEntries());
}

async function applyResultsPath(path) {
  try {
    const result = await backend({ action: "setResultsPath", algo: "catalog", path });
    $("[data-results-path]").value = result.path;
    setPathState("results will be written here");
    return result.path;
  } catch (error) {
    setPathState(error.message, true);
    throw error;
  }
}
async function browseFolder(path) {
  const result = await backend({ action: "browseResultsPath", algo: "catalog", path });
  currentPickerPath = result.path;
  $("[data-folder-path]").value = result.path;
  const list = $("[data-folder-list]");
  list.replaceChildren();
  result.directories.forEach(name => {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "folder-entry";
    button.textContent = name;
    button.addEventListener("dblclick", () => browseFolder(`${currentPickerPath}/${name}`));
    button.addEventListener("click", () => { $("[data-folder-state]").textContent = `Double-click to open ${name}`; });
    list.append(button);
  });
  $("[data-folder-parent]").onclick = () => browseFolder(result.parent);
  $("[data-folder-state]").textContent = `${result.directories.length} child folders`;
}
async function openFolderPicker() {
  const dialog = $("[data-folder-dialog]");
  await browseFolder($("[data-results-path]").value);
  dialog.showModal();
}
function bindOutputControls() {
  const input = $("[data-results-path]");
  input.addEventListener("change", () => applyResultsPath(input.value).catch(() => {}));
  input.addEventListener("keydown", event => {
    if (event.key === "Enter") { event.preventDefault(); input.blur(); }
  });
  $("[data-clear-path]").addEventListener("click", () => applyResultsPath(catalogInfo.defaultResultsPath));
  $("[data-pick-path]").addEventListener("click", () => openFolderPicker().catch(error => setPathState(error.message, true)));
  $("[data-folder-path]").addEventListener("keydown", event => {
    if (event.key === "Enter") { event.preventDefault(); browseFolder(event.currentTarget.value).catch(error => { $("[data-folder-state]").textContent = error.message; }); }
  });
  $("[data-folder-select]").addEventListener("click", async () => {
    await applyResultsPath(currentPickerPath);
    $("[data-folder-dialog]").close();
  });
}

async function boot() {
  createInteropBubbles();
  binding = await loadTyrCrypto();
  catalogInfo = await backend({ action: "catalog", algo: "catalog" });
  catalog = catalogInfo.entries;
  $("[data-results-path]").value = catalogInfo.resultsPath;
  setPathState("results will be written here");
  createCatalogCards();
  createFamilyButtons();
  bindOutputControls();
  document.querySelectorAll("[data-filter]").forEach(button => button.addEventListener("click", () => selectFilter(button.dataset.filter)));
  $("[data-run]").addEventListener("click", runSelection);
  $("[data-stop-all]").addEventListener("click", stopAllCatalogJobs);
  refreshSelection();
  if (catalogInfo.smokeMode) {
    selectedFilter = "interop";
    refreshSelection();
    await runSelection();
  } else {
    setStatus(`WASM ABI ${binding.abiVersion()} online / ${catalog.length} paired groups ready`);
    await pollCatalogJobs();
    pollTimer = setInterval(pollCatalogJobs, 500);
  }
}
async function bootWhenWebUiReady() {
  let lastError;
  for (let attempt = 0; attempt < 100; attempt += 1) {
    try {
      const probeBytes = seed("webui-transport-probe", 4096);
      const probe = JSON.parse(await callNative("interop", JSON.stringify({ action: "echo", algo: "transport", message: encode(probeBytes) })));
      if (!probe.ok || !equal(probeBytes, decode(probe.bytes))) throw new Error("WebUI byte transport probe failed");
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
