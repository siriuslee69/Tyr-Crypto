## ===================================================================
## | Asymmetric Benchmark Report Renderer                            |
## | -> Merge JSON benchmark runs and emit one sortable HTML report  |
## ===================================================================

import std/[json, os, parseopt, strutils]

type
  RenderArgs = object
    outPath: string
    inputs: seq[string]

proc parseArgs(): RenderArgs =
  var
    p = initOptParser(commandLineParams())
  while true:
    p.next()
    case p.kind
    of cmdEnd:
      break
    of cmdLongOption, cmdShortOption:
      case p.key
      of "out", "o":
        result.outPath = p.val
      else:
        discard
    of cmdArgument:
      result.inputs.add(p.key)

proc inferDeviceLabel(path: string): string =
  let lower = path.toLowerAscii()
  if lower.contains("desktop"):
    return "desktop_avx2"
  if lower.contains("motorola") or lower.contains("phone") or lower.contains("android"):
    return "motorola_edge_50_fusion"
  result = splitFile(path).name

proc inferDeviceKind(path: string): string =
  let lower = path.toLowerAscii()
  if lower.contains("desktop"):
    return "desktop"
  if lower.contains("motorola") or lower.contains("phone") or lower.contains("android"):
    return "phone"
  result = "unknown"

proc inferDeviceModel(path: string): string =
  let lower = path.toLowerAscii()
  if lower.contains("desktop"):
    return "Windows x64 workstation"
  if lower.contains("motorola") or lower.contains("phone") or lower.contains("android"):
    return "motorola_edge_50_fusion"
  result = ""

proc inferDeviceOs(path: string): string =
  let lower = path.toLowerAscii()
  if lower.contains("desktop"):
    return "Windows"
  if lower.contains("motorola") or lower.contains("phone") or lower.contains("android"):
    return "Android"
  result = ""

proc normalizeRun(root: JsonNode, path: string): JsonNode =
  var
    run = root
  if not run.hasKey("metadata"):
    run["metadata"] = newJObject()
  if run["metadata"].getOrDefault("device_label").getStr().len == 0:
    run["metadata"]["device_label"] = %inferDeviceLabel(path)
  if run["metadata"].getOrDefault("device_kind").getStr().len == 0:
    run["metadata"]["device_kind"] = %inferDeviceKind(path)
  if run["metadata"].getOrDefault("device_model").getStr().len == 0:
    run["metadata"]["device_model"] = %inferDeviceModel(path)
  if run["metadata"].getOrDefault("device_os").getStr().len == 0:
    run["metadata"]["device_os"] = %inferDeviceOs(path)
  run["metadata"]["source_file"] = %path
  result = run

proc buildHtml(data: JsonNode): string =
  result = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Tyr Asymmetric Benchmark Matrix</title>
  <link rel="preconnect" href="https://fonts.googleapis.com" />
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
  <link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;600;700&family=Manrope:wght@400;500;600;700&display=swap" rel="stylesheet" />
  <style>
    :root {
      --surface: #121419;
      --surface-low: rgba(20, 23, 29, 0.78);
      --surface-high: rgba(32, 36, 43, 0.82);
      --surface-top: rgba(43, 48, 56, 0.9);
      --surface-void: #060709;
      --page-start: #ddeaf6;
      --page-mid: #7e98b7;
      --page-end: #0b1118;
      --panel-fill: rgba(27, 36, 46, 0.84);
      --shell-fill: rgba(22, 30, 39, 0.8);
      --input-bg: rgba(13, 20, 28, 0.9);
      --input-border: rgba(232, 239, 248, 0.24);
      --menu-button-bg: rgba(10, 18, 26, 0.92);
      --menu-button-hover-bg: rgba(25, 39, 54, 0.96);
      --menu-button-active-bg: #eef5ff;
      --menu-button-text: #f9fbff;
      --menu-button-active-text: #071018;
      --line: rgba(223, 232, 243, 0.14);
      --line-strong: rgba(184, 208, 234, 0.34);
      --text: #f4f7fb;
      --muted: #a4afbc;
      --primary: #eef5ff;
      --primary-strong: #a9d0ff;
      --secondary: #2ff801;
      --tertiary: #ff78ff;
      --warn: #ffd166;
      --danger: #ff7b8a;
      --shadow: 0 18px 40px rgba(0, 0, 0, 0.44);
      --font-display: "Space Grotesk", sans-serif;
      --font-body: "Manrope", sans-serif;
      --radius: 0px;
      --gap: 18px;
    }

    * { box-sizing: border-box; }
    html, body { margin: 0; min-height: 100%; }
    body {
      font-family: var(--font-body);
      color: var(--text);
      background:
        linear-gradient(142deg, var(--page-start) 0%, var(--page-mid) 42%, var(--page-end) 100%);
    }

    body::before,
    body::after {
      content: "";
      position: fixed;
      inset: 0;
      pointer-events: none;
    }

    body::before {
      background:
        radial-gradient(circle at 15% 12%, rgba(238, 245, 255, 0.16), transparent 34%),
        radial-gradient(circle at 82% 18%, rgba(169, 208, 255, 0.12), transparent 30%),
        repeating-linear-gradient(
          180deg,
          rgba(255, 255, 255, 0.03) 0 2px,
          rgba(255, 255, 255, 0.01) 2px 6px,
          transparent 6px 12px
        );
      mix-blend-mode: screen;
      opacity: 0.8;
    }

    body::after {
      background-image:
        linear-gradient(rgba(255,255,255,0.04) 1px, transparent 1px),
        linear-gradient(90deg, rgba(169,208,255,0.04) 1px, transparent 1px);
      background-size: 44px 44px;
      mask-image: linear-gradient(180deg, rgba(0,0,0,0.75), transparent 92%);
      opacity: 0.22;
    }

    .shell {
      width: min(1680px, calc(100vw - 36px));
      margin: 18px auto 28px;
      display: grid;
      gap: var(--gap);
      position: relative;
      z-index: 1;
    }

    .panel {
      background: var(--panel-fill);
      border: 1px solid var(--line);
      box-shadow: var(--shadow);
      backdrop-filter: blur(10px);
    }

    .topbar {
      display: grid;
      grid-template-columns: minmax(260px, 1.6fr) 1fr 1fr;
      gap: 12px;
      padding: 12px;
      align-items: start;
    }

    .panel-headline {
      display: grid;
      gap: 8px;
    }

    .eyebrow {
      margin: 0;
      text-transform: uppercase;
      letter-spacing: 0.18em;
      font-size: 11px;
      color: var(--muted);
    }

    h1, h2, h3, p { margin: 0; }
    h1 {
      font-family: var(--font-display);
      font-size: clamp(1.35rem, 1.1rem + 1vw, 2rem);
    }

    .muted {
      color: var(--muted);
    }

    input, button, select {
      font: inherit;
      color: inherit;
      border-radius: 0;
    }

    input {
      width: 100%;
      border: 1px solid transparent;
      border-bottom-color: var(--input-border);
      background: var(--input-bg);
      padding: 14px 14px 13px;
    }

    .menu-stack,
    .control-stack {
      display: grid;
      gap: 10px;
    }

    .button-row,
    .chip-row {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
    }

    .nav-button,
    .chip,
    .sort-button {
      border: 1px solid var(--line);
      background: var(--menu-button-bg);
      color: var(--menu-button-text);
      padding: 10px 12px;
      cursor: pointer;
      transition: background 0.4s ease, color 0.4s ease, border-color 0.4s ease, transform 0.4s ease;
    }

    .nav-button:hover,
    .chip:hover,
    .sort-button:hover {
      background: var(--menu-button-hover-bg);
      border-color: var(--line-strong);
      transform: translateY(-1px);
    }

    .is-active {
      background: var(--menu-button-active-bg) !important;
      color: var(--menu-button-active-text) !important;
      border-color: rgba(255,255,255,0.9) !important;
    }

    .metrics {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(170px, 1fr));
      gap: 12px;
      padding: 12px;
    }

    .metric-card {
      padding: 14px;
      background: var(--surface-low);
      border: 1px solid var(--line);
      display: grid;
      gap: 6px;
    }

    .metric-label {
      font-size: 12px;
      color: var(--muted);
      text-transform: uppercase;
      letter-spacing: 0.12em;
    }

    .metric-value {
      font-family: var(--font-display);
      font-size: 1.35rem;
    }

    .run-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
      gap: 12px;
      padding: 12px;
    }

    .run-card {
      padding: 14px;
      background: rgba(12, 19, 26, 0.82);
      border: 1px solid var(--line);
      display: grid;
      gap: 8px;
    }

    .run-meta {
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 6px 12px;
      font-size: 0.92rem;
    }

    .table-shell {
      padding: 12px;
      display: grid;
      gap: 12px;
    }

    .table-wrap {
      overflow: auto;
      max-height: calc(100vh - 320px);
      border: 1px solid var(--line);
      background: rgba(8, 12, 18, 0.7);
    }

    table {
      width: 100%;
      border-collapse: collapse;
      min-width: 1200px;
    }

    th, td {
      padding: 10px 12px;
      border-bottom: 1px solid var(--line);
      text-align: left;
      vertical-align: top;
      white-space: nowrap;
      font-size: 0.92rem;
    }

    th {
      position: sticky;
      top: 0;
      z-index: 1;
      background: rgba(19, 26, 35, 0.96);
      font-family: var(--font-display);
      font-size: 0.82rem;
      text-transform: uppercase;
      letter-spacing: 0.1em;
    }

    tbody tr:nth-child(odd) {
      background: rgba(255, 255, 255, 0.02);
    }

    tbody tr:hover {
      background: rgba(169, 208, 255, 0.08);
    }

    .pill {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 4px 8px;
      border: 1px solid var(--line);
      background: rgba(255,255,255,0.04);
    }

    .note {
      padding: 12px;
      background: rgba(255, 209, 102, 0.1);
      border: 1px solid rgba(255, 209, 102, 0.35);
      color: #fff6d8;
    }

    @media (max-width: 1080px) {
      .topbar {
        grid-template-columns: 1fr;
      }
      .table-wrap {
        max-height: none;
      }
    }
  </style>
</head>
<body>
  <main class="shell">
    <section class="topbar panel">
      <div class="panel-headline">
        <p class="eyebrow">Tyr Benchmark Matrix</p>
        <h1>Asymmetric Desktop + Motorola Timing Report</h1>
        <p class="muted">Summary timings and full aggregated function timings merged into one sortable report.</p>
      </div>

      <div class="control-stack">
        <input id="search-input" type="search" placeholder="Search family, variant, backend, function, device" />
        <div class="button-row" id="kind-buttons"></div>
      </div>

      <div class="menu-stack">
        <div class="button-row" id="sort-buttons"></div>
        <div class="button-row">
          <button id="sort-direction" class="nav-button" type="button">Descending</button>
          <button id="reset-button" class="nav-button" type="button">Reset Filters</button>
        </div>
      </div>
    </section>

    <section class="panel metrics" id="metrics"></section>
    <section class="panel run-grid" id="run-grid"></section>

    <section class="panel table-shell">
      <div class="chip-row" id="device-chips"></div>
      <div class="chip-row" id="family-chips"></div>
      <div class="note" id="report-note">
        Rows are filtered client-side. Summary rows are wall-clock nanoseconds. Function rows are Otter timing ticks aggregated per function name within each benchmark group.
      </div>
      <div class="table-wrap">
        <table>
          <thead id="table-head"></thead>
          <tbody id="table-body"></tbody>
        </table>
      </div>
    </section>
  </main>

  <script id="bench-json" type="application/json">""" & data.pretty() & """</script>
  <script>
    const report = JSON.parse(document.getElementById("bench-json").textContent);
    const runs = report.runs || [];
    const rows = runs.flatMap((run) => {
      const meta = run.metadata || {};
      return (run.rows || []).map((row) => ({ ...row, __meta: meta }));
    });

    const state = {
      kind: "summary",
      search: "",
      sortKey: "avg_ns_per_op",
      sortDir: "desc",
      devices: new Set(),
      families: new Set(),
    };

    const kindButtons = document.getElementById("kind-buttons");
    const sortButtons = document.getElementById("sort-buttons");
    const deviceChips = document.getElementById("device-chips");
    const familyChips = document.getElementById("family-chips");
    const tableHead = document.getElementById("table-head");
    const tableBody = document.getElementById("table-body");
    const metrics = document.getElementById("metrics");
    const runGrid = document.getElementById("run-grid");
    const searchInput = document.getElementById("search-input");
    const sortDirection = document.getElementById("sort-direction");
    const resetButton = document.getElementById("reset-button");

    const modeColumns = {
      summary: [
        ["device", (row) => row.__meta.device_label || row.device_label || ""],
        ["family", (row) => row.family || ""],
        ["variant", (row) => row.variant || ""],
        ["implementation", (row) => row.implementation || ""],
        ["backend", (row) => row.backend || ""],
        ["operation", (row) => row.operation || ""],
        ["loops", (row) => row.loops ?? ""],
        ["warmup", (row) => row.warmup ?? ""],
        ["ops/call", (row) => row.ops_per_call ?? ""],
        ["avg ns/op", (row) => formatNumber(row.avg_ns_per_op)],
        ["avg ns/call", (row) => formatNumber(row.avg_ns_per_call)],
        ["total ns", (row) => formatInt(row.total_ns)],
      ],
      function: [
        ["device", (row) => row.__meta.device_label || row.device_label || ""],
        ["family", (row) => row.family || ""],
        ["variant", (row) => row.variant || ""],
        ["implementation", (row) => row.implementation || ""],
        ["backend", (row) => row.backend || ""],
        ["group", (row) => row.group_name || ""],
        ["function", (row) => row.function_name || ""],
        ["loops", (row) => row.loops ?? ""],
        ["calls", (row) => row.call_count ?? ""],
        ["avg ticks", (row) => formatInt(row.avg_ticks)],
        ["max ticks", (row) => formatInt(row.max_ticks)],
        ["total ticks", (row) => formatInt(row.total_ticks)],
      ],
    };

    const modeSortKeys = {
      summary: [
        ["avg_ns_per_op", "ns/op"],
        ["avg_ns_per_call", "ns/call"],
        ["total_ns", "total"],
        ["family", "family"],
        ["variant", "variant"],
        ["device", "device"],
      ],
      function: [
        ["avg_ticks", "avg ticks"],
        ["max_ticks", "max ticks"],
        ["total_ticks", "total ticks"],
        ["function_name", "function"],
        ["family", "family"],
        ["device", "device"],
      ],
    };

    function formatNumber(value) {
      if (value === null || value === undefined || Number.isNaN(Number(value))) return "";
      return Number(value).toLocaleString(undefined, { maximumFractionDigits: 2 });
    }

    function formatInt(value) {
      if (value === null || value === undefined || Number.isNaN(Number(value))) return "";
      return Number(value).toLocaleString();
    }

    function deviceName(row) {
      return row.__meta.device_label || row.device_label || "";
    }

    function getSortValue(row, key) {
      if (key === "device") return deviceName(row);
      return row[key] ?? "";
    }

    function compareRows(a, b) {
      const aVal = getSortValue(a, state.sortKey);
      const bVal = getSortValue(b, state.sortKey);
      const aNum = Number(aVal);
      const bNum = Number(bVal);
      let cmp = 0;
      if (!Number.isNaN(aNum) && !Number.isNaN(bNum) && String(aVal).length > 0 && String(bVal).length > 0) {
        cmp = aNum - bNum;
      } else {
        cmp = String(aVal).localeCompare(String(bVal));
      }
      return state.sortDir === "asc" ? cmp : -cmp;
    }

    function rowMatchesSearch(row) {
      if (!state.search) return true;
      const haystack = [
        row.family,
        row.variant,
        row.implementation,
        row.backend,
        row.operation,
        row.group_name,
        row.function_name,
        deviceName(row),
      ].join(" ").toLowerCase();
      return haystack.includes(state.search);
    }

    function rowVisible(row) {
      if (row.kind !== state.kind) return false;
      if (state.devices.size > 0 && !state.devices.has(deviceName(row))) return false;
      if (state.families.size > 0 && !state.families.has(row.family)) return false;
      return rowMatchesSearch(row);
    }

    function visibleRows() {
      return rows.filter(rowVisible).sort(compareRows);
    }

    function renderKindButtons() {
      kindButtons.innerHTML = "";
      ["summary", "function"].forEach((kind) => {
        const button = document.createElement("button");
        button.className = "nav-button" + (state.kind === kind ? " is-active" : "");
        button.textContent = kind === "summary" ? "Summary Rows" : "Function Rows";
        button.onclick = () => {
          state.kind = kind;
          state.sortKey = modeSortKeys[kind][0][0];
          render();
        };
        kindButtons.appendChild(button);
      });
    }

    function renderSortButtons() {
      sortButtons.innerHTML = "";
      modeSortKeys[state.kind].forEach(([key, label]) => {
        const button = document.createElement("button");
        button.className = "sort-button" + (state.sortKey === key ? " is-active" : "");
        button.textContent = label;
        button.onclick = () => {
          state.sortKey = key;
          renderTable();
          renderSortButtons();
        };
        sortButtons.appendChild(button);
      });
    }

    function renderChips(container, values, selectedSet, onToggle) {
      container.innerHTML = "";
      values.forEach((value) => {
        const button = document.createElement("button");
        button.className = "chip" + (selectedSet.has(value) ? " is-active" : "");
        button.textContent = value;
        button.onclick = () => onToggle(value);
        container.appendChild(button);
      });
    }

    function renderFilters() {
      const activeRows = rows.filter((row) => row.kind === state.kind);
      const devices = [...new Set(activeRows.map(deviceName).filter(Boolean))].sort();
      const families = [...new Set(activeRows.map((row) => row.family).filter(Boolean))].sort();
      renderChips(deviceChips, devices, state.devices, (value) => {
        if (state.devices.has(value)) state.devices.delete(value); else state.devices.add(value);
        renderTable();
        renderFilters();
        renderMetrics();
      });
      renderChips(familyChips, families, state.families, (value) => {
        if (state.families.has(value)) state.families.delete(value); else state.families.add(value);
        renderTable();
        renderFilters();
        renderMetrics();
      });
    }

    function renderMetrics() {
      const visible = visibleRows();
      const uniqueFunctions = new Set(visible.map((row) => row.function_name).filter(Boolean));
      const totalRuns = runs.length;
      const totalDevices = new Set(runs.map((run) => (run.metadata || {}).device_label).filter(Boolean)).size;
      const totalFamilies = new Set(visible.map((row) => row.family).filter(Boolean)).size;
      const metricsData = [
        ["Visible Rows", visible.length],
        ["Report Mode", state.kind],
        ["Devices", totalDevices],
        ["Families", totalFamilies],
        ["Runs Loaded", totalRuns],
        ["Functions Visible", uniqueFunctions.size],
      ];
      metrics.innerHTML = "";
      metricsData.forEach(([label, value]) => {
        const card = document.createElement("div");
        card.className = "metric-card";
        card.innerHTML = `<span class="metric-label">${label}</span><strong class="metric-value">${value}</strong>`;
        metrics.appendChild(card);
      });
    }

    function renderRunGrid() {
      runGrid.innerHTML = "";
      runs.forEach((run) => {
        const meta = run.metadata || {};
        const card = document.createElement("div");
        card.className = "run-card";
        card.innerHTML = `
          <div>
            <p class="eyebrow">${meta.device_kind || "device"}</p>
            <h3>${meta.device_label || "unnamed run"}</h3>
          </div>
          <p class="muted">${meta.device_model || ""} ${meta.device_os ? " / " + meta.device_os : ""}</p>
          <div class="run-meta">
            <span>Profile</span><strong>${meta.profile || ""}</strong>
            <span>Phase</span><strong>${meta.phase || "both"}</strong>
            <span>Loop Scale</span><strong>${meta.loop_scale ?? 1.0}</strong>
            <span>Backend</span><strong>${meta.compiled_backend || ""}</strong>
            <span>Generated</span><strong>${meta.generated_local || ""}</strong>
            <span>Features</span><strong>${(meta.features || []).join(", ")}</strong>
          </div>
        `;
        runGrid.appendChild(card);
      });
    }

    function renderTable() {
      const visible = visibleRows();
      const columns = modeColumns[state.kind];
      tableHead.innerHTML = "<tr>" + columns.map(([label]) => `<th>${label}</th>`).join("") + "</tr>";
      tableBody.innerHTML = visible.map((row) => {
        const cells = columns.map(([, getter]) => `<td>${getter(row) ?? ""}</td>`).join("");
        return `<tr>${cells}</tr>`;
      }).join("");
    }

    function render() {
      renderKindButtons();
      renderSortButtons();
      renderFilters();
      renderMetrics();
      renderRunGrid();
      renderTable();
    }

    searchInput.addEventListener("input", (event) => {
      state.search = event.target.value.trim().toLowerCase();
      renderMetrics();
      renderTable();
    });

    sortDirection.onclick = () => {
      state.sortDir = state.sortDir === "asc" ? "desc" : "asc";
      sortDirection.textContent = state.sortDir === "asc" ? "Ascending" : "Descending";
      renderTable();
    };

    resetButton.onclick = () => {
      state.search = "";
      searchInput.value = "";
      state.devices.clear();
      state.families.clear();
      state.kind = "summary";
      state.sortKey = "avg_ns_per_op";
      state.sortDir = "desc";
      sortDirection.textContent = "Descending";
      render();
    };

    render();
  </script>
</body>
</html>
"""

when isMainModule:
  let args = parseArgs()
  var
    runs = newJArray()
    root: JsonNode
    inputPath: string = ""
  if args.inputs.len == 0:
    quit("No input JSON files provided.")
  for path in args.inputs:
    inputPath = absolutePath(path)
    root = parseFile(inputPath)
    runs.add(normalizeRun(root, inputPath))
  root = %*{
    "runs": runs
  }
  if args.outPath.len == 0:
    quit("Missing --out path.")
  createDir(parentDir(args.outPath))
  writeFile(args.outPath, buildHtml(root))
