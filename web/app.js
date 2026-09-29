// Front end for the nthunt web analyzer. All Python work happens in engine-worker.js.

const $ = (id) => document.getElementById(id);
const MAX_MB = 400;
const WARN_MB = 150;
const ROW_LIMIT = 1000;

// Friendlier names for the commands in nthunt/cli.py. Unknown commands still
// appear, using their docstring, so new detectors need no front-end changes.
const LABELS = {
  summary: "Capture summary",
  beacon: "Beaconing (possible C2)",
  dns: "Suspicious DNS",
  scan: "Port and host scanning",
};
// Plain-language descriptions (from the README's toolkit table). The function's
// docstring is used for any command not listed here.
const BLURBS = {
  summary: "Top talkers, protocols, conversations and DNS queries. The lay of the land before you hunt.",
  beacon: "Hosts calling out at suspiciously regular intervals, a common sign of command-and-control.",
  dns: "High-entropy or unusually long domain names that can point to DGA malware or DNS tunneling.",
  scan: "Hosts touching many ports or many hosts in a short window, as reconnaissance does.",
};
const PARAM_HELP = {
  top_n: "How many entries to list in each top-N table.",
  min_connections: "Skip host pairs with fewer connections than this.",
  max_jitter: "Most timing variation allowed (stdev ÷ mean of the gaps). Lower is stricter.",
  entropy_threshold: "Flag names more random-looking than this, in bits per character.",
  max_label_len: "Flag any single DNS label longer than this many characters.",
  port_threshold: "Ports one source must hit on one target to count as a vertical scan.",
  host_threshold: "Targets one source must hit on one port to count as a horizontal scan.",
  window_seconds: "Length of the sliding time window, in seconds.",
};

const state = {
  worker: null,
  ready: false,
  busy: false,
  detectors: [],
  capture: null, // {name, size, packets, start, end, histogram}
  pendingFile: null,
  results: new Map(), // name -> {payload, params}
  runSeq: 0,
  demo: false,
  waiters: new Map(),
};

/* ---------- engine ---------- */

function setEngine(text, mode = "loading") {
  $("engine").dataset.state = mode;
  $("engineText").textContent = text;
}

function startEngine() {
  state.worker = new Worker("engine-worker.js");
  state.worker.onmessage = ({ data }) => {
    switch (data.type) {
      case "status":
        setEngine(data.text);
        break;
      case "ready":
        state.ready = true;
        state.detectors = data.info.detectors;
        setEngine(`Ready. nthunt ${data.info.version}`, "ready");
        renderDetectors();
        if (state.demo) $("demoBtn").textContent = "Running the demo…";
        if (state.pendingFile) {
          const f = state.pendingFile;
          state.pendingFile = null;
          readCapture(f.name, f.bytes, f.size);
        }
        break;
      case "progress":
        setEngine(`Reading capture: ${data.packets.toLocaleString()} packets`, "busy");
        break;
      case "loaded":
        onLoaded(data.capture);
        break;
      case "result": {
        const done = state.waiters.get(data.id);
        state.waiters.delete(data.id);
        done && done(data.payload);
        break;
      }
      case "fatal":
        onFatal(data);
        break;
    }
  };
  state.worker.onerror = (e) => onFatal({ stage: "boot", message: e.message || "The engine worker crashed." });
  state.worker.postMessage({ type: "boot", siteBase: new URL(".", location.href).href });
}

function onFatal({ stage, message }) {
  if (state.demo) endDemo();
  if (stage === "boot") {
    setEngine("Engine failed to start", "error");
    $("detectors").innerHTML = "";
    const p = el("p", "notice notice--error");
    p.textContent = `The Python engine couldn’t start (${message}). Check your internet connection and reload the page. The first visit downloads about 15 MB, which is cached afterwards.`;
    $("detectors").append(p);
  } else if (stage === "load") {
    state.busy = false;
    setEngine("Ready", "ready");
    $("drop").classList.remove("is-busy");
    const failed = state.capture?.name || "That file";
    state.capture = state.prevCapture; // the previous capture (if any) is still loaded
    showLoadError(`${failed} couldn’t be read as a packet capture (${message.replace(/^[\w.]+Exception: /, "")}). Make sure it’s a .pcap or .pcapng file saved from Wireshark or tcpdump.`);
  } else {
    state.busy = false;
    setEngine("Ready", "ready");
    toast(`Something went wrong: ${message}`);
  }
  updateRunBar();
}

/* ---------- loading a capture ---------- */

function showLoadError(msg) {
  const box = $("loadError");
  box.textContent = msg;
  box.hidden = !msg;
}

async function acceptFile(file) {
  showLoadError("");
  if (!file) return;
  if (!/\.(pcap|pcapng|cap)$/i.test(file.name)) {
    showLoadError(`“${file.name}” doesn’t look like a packet capture. Choose a .pcap, .pcapng or .cap file.`);
    return;
  }
  const mb = file.size / 1048576;
  if (mb > MAX_MB) {
    showLoadError(`This capture is ${mb.toFixed(0)} MB, which is more than a browser tab can hold in memory. Trim it in Wireshark (File › Export Specified Packets) or run the CLI instead.`);
    return;
  }
  if (mb > WARN_MB && !confirm(`This capture is ${mb.toFixed(0)} MB. Large files can take several minutes and use a lot of memory. Continue?`)) return;
  readCapture(file.name, await file.arrayBuffer(), file.size);
}

async function loadSample() {
  showLoadError("");
  $("sampleBtn").disabled = true;
  try {
    const r = await fetch("samples/synthetic-lab.pcap");
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    const buf = await r.arrayBuffer();
    readCapture("synthetic-lab.pcap", buf, buf.byteLength);
  } catch (e) {
    showLoadError(`Couldn’t download the sample capture (${e.message}).`);
    if (state.demo) endDemo();
  } finally {
    $("sampleBtn").disabled = false;
  }
}

function readCapture(name, bytes, size) {
  if (!state.ready) {
    state.pendingFile = { name, bytes, size };
    showNotice(`Got ${name}. It will be read as soon as the Python engine finishes loading.`);
    return;
  }
  clearNotice();
  state.busy = true;
  state.prevCapture = state.capture?.packets ? state.capture : null;
  state.capture = { name, size };
  state.results.clear();
  resetFindings();
  $("drop").classList.add("is-busy");
  setEngine("Reading capture", "busy");
  updateRunBar();
  state.worker.postMessage({ type: "load", name, bytes }, [bytes]);
}

function onLoaded(info) {
  state.busy = false;
  Object.assign(state.capture, info);
  setEngine("Ready", "ready");
  $("drop").classList.remove("is-busy");
  $("drop").hidden = true;
  $("capture").hidden = false;
  $("sampleLine").hidden = true;
  $("capName").textContent = state.capture.name;
  $("capPackets").textContent = info.packets.toLocaleString();
  $("capSize").textContent = fmtBytes(state.capture.size);
  if (info.packets) {
    $("capSpan").textContent = fmtDuration(info.end - info.start);
    $("capStart").textContent = fmtTime(info.start);
    $("tlStart").textContent = fmtTime(info.start, true);
    $("tlEnd").textContent = fmtTime(info.end, true);
    drawTimeline(info.histogram);
  } else {
    $("capSpan").textContent = "–";
    $("capStart").textContent = "–";
    showLoadError("The file was read but contains no packets.");
  }
  updateRunBar();
  if (state.demo) {
    // Demo mode: select every built detector and run straight away.
    document.querySelectorAll(".det__check:not(:disabled)").forEach((c) => (c.checked = true));
    updateRunBar();
    if (selected().length) runSelected().finally(endDemo);
    else endDemo();
    return;
  }
  $("capture").scrollIntoView({ behavior: matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth", block: "nearest" });
}

function drawTimeline(counts) {
  const svg = $("timeline");
  const W = 900, H = 84, pad = 6;
  svg.setAttribute("viewBox", `0 0 ${W} ${H}`);
  const max = Math.max(...counts, 1);
  const bw = W / counts.length;
  const bars = counts
    .map((c, i) => {
      const h = c ? Math.max(2, ((H - pad * 2) * c) / max) : 0;
      return `<rect x="${(i * bw + 1).toFixed(1)}" y="${(H - pad - h).toFixed(1)}" width="${(bw - 2).toFixed(1)}" height="${h.toFixed(1)}" rx="1"><title>${c.toLocaleString()} packets</title></rect>`;
    })
    .join("");
  svg.innerHTML = `<line x1="0" x2="${W}" y1="${H - pad + 0.5}" y2="${H - pad + 0.5}" stroke="#3a4757"/><g fill="#f2a93b">${bars}</g>`;
}

/* ---------- one-click demo ---------- */

function startDemo() {
  if (state.busy) return;
  state.demo = true;
  const b = $("demoBtn");
  b.disabled = true;
  b.textContent = state.ready ? "Running the demo…" : "Starting the engine…";
  loadSample();
}

function endDemo() {
  state.demo = false;
  const b = $("demoBtn");
  b.disabled = false;
  b.textContent = "Run the demo again";
}

/* ---------- install as an app ---------- */

let installEvent = null;
function setupInstall() {
  if ("serviceWorker" in navigator && (location.protocol === "https:" || location.hostname === "localhost")) {
    navigator.serviceWorker.register("sw.js").catch((e) => console.debug("Service worker not registered:", e));
  }
  window.addEventListener("beforeinstallprompt", (e) => {
    e.preventDefault();
    installEvent = e;
    $("installBtn").hidden = false;
  });
  $("installBtn").addEventListener("click", async () => {
    if (!installEvent) return;
    installEvent.prompt();
    await installEvent.userChoice;
    installEvent = null;
    $("installBtn").hidden = true;
  });
  window.addEventListener("appinstalled", () => ($("installBtn").hidden = true));
}

/* ---------- detectors ---------- */

function renderDetectors() {
  const host = $("detectors");
  host.innerHTML = "";
  if (!state.detectors.length) {
    host.append(Object.assign(el("p", "placeholder"), { textContent: "nthunt/cli.py doesn’t register any commands yet." }));
    return;
  }
  const tpl = $("detectorTpl");
  for (const d of state.detectors) {
    const node = tpl.content.firstElementChild.cloneNode(true);
    node.dataset.name = d.name;
    const check = node.querySelector(".det__check");
    check.checked = d.built;
    check.disabled = !d.built;
    check.addEventListener("change", updateRunBar);
    node.querySelector(".det__name").textContent = LABELS[d.name] || titleCase(d.name);
    node.querySelector(".det__summary").textContent = BLURBS[d.name] || d.summary || `Runs ${d.function}.`;
    const badge = node.querySelector(".badge");
    badge.textContent = d.built ? "Ready" : "Not built yet";
    badge.classList.add(d.built ? "badge--ready" : "badge--stub");

    if (!d.built) {
      node.classList.add("is-stub");
      const todo = node.querySelector(".det__todo");
      todo.hidden = false;
      todo.innerHTML = `Still in development. Once <code>${esc(d.function)}</code> in <code>${esc(d.file)}</code> is implemented, it runs here automatically.`;
    }

    const settings = node.querySelector(".det__settings");
    if (!d.params.length || !d.built) {
      settings.remove();
    } else {
      const box = node.querySelector(".det__params");
      for (const p of d.params) box.append(paramField(d.name, p));
      node.querySelector(".det__reset").addEventListener("click", () => {
        for (const p of d.params) {
          const input = box.querySelector(`[data-param="${p.name}"]`);
          if (p.kind === "bool") input.checked = p.default;
          else input.value = p.default;
        }
      });
    }
    host.append(node);
  }
  updateRunBar();
}

function paramField(det, p) {
  const id = `p-${det}-${p.name}`;
  const wrap = el("div", "param");
  const label = el("label", "param__label");
  label.htmlFor = id;
  label.textContent = titleCase(p.name);
  let input;
  if (p.kind === "bool") {
    input = document.createElement("input");
    input.type = "checkbox";
    input.checked = p.default;
  } else {
    input = document.createElement("input");
    input.type = p.kind === "str" ? "text" : "number";
    input.value = p.default;
    if (p.kind === "int") { input.step = "1"; input.min = "0"; }
    if (p.kind === "float") { input.step = "any"; input.min = "0"; }
  }
  input.id = id;
  input.dataset.param = p.name;
  input.dataset.kind = p.kind;
  wrap.append(label, input);
  const help = PARAM_HELP[p.name];
  const hint = el("span", "param__help");
  hint.textContent = (help ? help + " " : "") + `Default: ${p.default}.`;
  wrap.append(hint);
  return wrap;
}

function readParams(name) {
  const node = document.querySelector(`.det[data-name="${name}"]`);
  const out = {};
  for (const input of node.querySelectorAll("[data-param]")) {
    const kind = input.dataset.kind;
    if (kind === "bool") out[input.dataset.param] = input.checked;
    else if (kind === "str") out[input.dataset.param] = input.value;
    else {
      const v = kind === "int" ? parseInt(input.value, 10) : parseFloat(input.value);
      if (Number.isNaN(v)) throw new Error(`“${titleCase(input.dataset.param)}” needs a number.`);
      out[input.dataset.param] = v;
    }
  }
  return out;
}

function selected() {
  return [...document.querySelectorAll(".det")].filter((n) => n.querySelector(".det__check:checked")).map((n) => n.dataset.name);
}

function updateRunBar() {
  const btn = $("runBtn");
  const why = $("runWhy");
  const builtCount = state.detectors.filter((d) => d.built).length;
  let reason = "";
  if (!state.ready) reason = "Waiting for the Python engine.";
  else if (!builtCount) reason = "No detectors are built yet. Implement one in nthunt/ and push to see it here.";
  else if (!state.capture || !state.capture.packets) reason = "Load a capture to run detectors.";
  else if (!selected().length) reason = "Select at least one detector.";
  else if (state.busy) reason = "Working…";
  btn.disabled = Boolean(reason);
  why.textContent = reason || `Runs on ${state.capture.packets.toLocaleString()} packets from ${state.capture.name}.`;
}

/* ---------- running ---------- */

function runOne(name, params) {
  const id = ++state.runSeq;
  return new Promise((resolve) => {
    state.waiters.set(id, resolve);
    state.worker.postMessage({ type: "run", id, name, params });
  });
}

async function runSelected() {
  const names = selected();
  let paramsByName;
  try {
    paramsByName = Object.fromEntries(names.map((n) => [n, readParams(n)]));
  } catch (e) {
    toast(e.message);
    return;
  }
  state.busy = true;
  updateRunBar();
  resetFindings();
  const panels = Object.fromEntries(names.map((n) => [n, makePanel(n)]));
  $("findings").innerHTML = "";
  for (const n of names) $("findings").append(panels[n]);
  $("findings").scrollIntoView({ behavior: matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth", block: "start" });

  for (const name of names) {
    setEngine(`Running ${LABELS[name] || name}`, "busy");
    panels[name].classList.add("panel--running");
    panels[name].querySelector(".panel__meta").textContent = "Running";
    const payload = await runOne(name, paramsByName[name]);
    state.results.set(name, { payload, params: paramsByName[name] });
    fillPanel(panels[name], name, payload, paramsByName[name]);
  }
  state.busy = false;
  setEngine("Ready", "ready");
  $("findingsTools").hidden = ![...state.results.values()].some((r) => r.payload.status === "ok");
  updateRunBar();
}

function resetFindings() {
  $("findings").innerHTML = '<p class="placeholder">Results show up here, one panel per detector.</p>';
  $("findingsTools").hidden = true;
}

/* ---------- findings ---------- */

function makePanel(name) {
  const p = el("article", "panel");
  p.innerHTML = `<header class="panel__head"><div><h3 class="panel__title"></h3><p class="panel__meta"></p></div><div class="panel__actions"></div></header><div class="panel__body"></div>`;
  p.querySelector(".panel__title").textContent = LABELS[name] || titleCase(name);
  p.querySelector(".panel__meta").textContent = "Queued";
  return p;
}

function fillPanel(panel, name, payload, params) {
  panel.classList.remove("panel--running");
  const meta = panel.querySelector(".panel__meta");
  const body = panel.querySelector(".panel__body");
  const actions = panel.querySelector(".panel__actions");
  const secs = `${payload.seconds < 1 ? payload.seconds.toFixed(2) : payload.seconds.toFixed(1)} s`;

  if (payload.status === "not_built") {
    panel.classList.add("panel--stub");
    meta.textContent = "Not built yet";
    body.innerHTML = `<p class="todo-steps">${esc(payload.message)}</p>`;
    return;
  }
  if (payload.status === "error") {
    panel.classList.add("panel--error");
    meta.textContent = `Stopped with an error after ${secs}`;
    body.innerHTML = `<p class="empty"><strong>${esc(payload.message)}</strong></p><details class="raw" open><summary>Python traceback</summary><pre></pre></details>`;
    body.querySelector("pre").textContent = payload.traceback;
    return;
  }

  const result = payload.result;
  const n = Array.isArray(result) ? result.length : null;
  if (n === null) {
    panel.classList.add("panel--info");
    meta.innerHTML = `Finished in ${secs}`;
  } else if (n === 0) {
    panel.classList.add("panel--clear");
    meta.innerHTML = `<span class="count">No findings</span> in ${secs}`;
  } else {
    panel.classList.add("panel--hit");
    meta.innerHTML = `<span class="count">${n.toLocaleString()} finding${n === 1 ? "" : "s"}</span> in ${secs}`;
  }

  body.append(renderValue(result, 0));
  const raw = el("details", "raw");
  raw.innerHTML = "<summary>Raw JSON (same as the CLI prints)</summary><pre></pre>";
  raw.querySelector("pre").textContent = JSON.stringify(result, null, 2);
  body.append(raw);

  actions.append(
    button("Copy for report", () => copyText(toMarkdown(name, result, params), "Copied as Markdown. Paste it into the report’s Toolkit Output section.")),
    button("Download JSON", () => download(`${stem()}-${name}.json`, exportRecord(name, result, params)))
  );
}

const isScalar = (v) => v === null || ["string", "number", "boolean"].includes(typeof v);
const isPlainObj = (v) => v && typeof v === "object" && !Array.isArray(v);

function renderValue(v, depth) {
  if (isScalar(v)) return stats({ value: v });
  if (Array.isArray(v)) {
    if (!v.length) {
      const p = el("p", "empty");
      p.textContent = depth === 0 ? "Nothing matched with these settings. Try loosening a threshold under Settings if you expected a hit." : "None.";
      return p;
    }
    if (v.every(isPlainObj) && v.every((o) => Object.values(o).every(isScalar))) {
      const cols = [...new Set(v.flatMap(Object.keys))];
      return table(cols.map(titleCase), v.map((o) => cols.map((c) => o[c])));
    }
    if (v.every((x) => Array.isArray(x) && x.length === 2 && isScalar(x[0]) && typeof x[1] === "number")) {
      return table(["Value", "Count"], v);
    }
    if (v.every(isScalar)) return table(["Value"], v.map((x) => [x]));
    return pre(v);
  }
  if (isPlainObj(v)) {
    const entries = Object.entries(v);
    if (depth > 0) {
      if (entries.every(([, x]) => isScalar(x))) {
        const rows = entries.slice();
        if (rows.every(([, x]) => typeof x === "number")) rows.sort((a, b) => b[1] - a[1]);
        return table(["Key", "Value"], rows);
      }
      return pre(v);
    }
    const frag = document.createDocumentFragment();
    const scalars = Object.fromEntries(entries.filter(([, x]) => isScalar(x)));
    if (Object.keys(scalars).length) frag.append(stats(scalars));
    for (const [k, x] of entries.filter(([, x]) => !isScalar(x))) {
      const block = el("section", "block");
      const h = el("h4");
      h.textContent = titleCase(k);
      block.append(h, renderValue(x, depth + 1));
      frag.append(block);
    }
    return frag;
  }
  return pre(v);
}

function stats(obj) {
  const dl = el("dl", "stats");
  for (const [k, v] of Object.entries(obj)) {
    const d = el("div");
    d.innerHTML = "<dt></dt><dd></dd>";
    d.querySelector("dt").textContent = titleCase(k);
    d.querySelector("dd").textContent = fmtCell(k, v);
    dl.append(d);
  }
  return dl;
}

function table(headers, rows) {
  const wrap = el("div");
  const scroller = el("div", "tablewrap");
  const t = document.createElement("table");
  const thead = document.createElement("thead");
  const tr = document.createElement("tr");
  headers.forEach((h, i) => {
    const th = document.createElement("th");
    th.scope = "col";
    th.tabIndex = 0;
    th.textContent = h;
    const sort = () => sortTable(t, i, th);
    th.addEventListener("click", sort);
    th.addEventListener("keydown", (e) => (e.key === "Enter" || e.key === " ") && (e.preventDefault(), sort()));
    tr.append(th);
  });
  thead.append(tr);
  const tbody = document.createElement("tbody");
  for (const row of rows.slice(0, ROW_LIMIT)) {
    const r = document.createElement("tr");
    row.forEach((v, i) => {
      const td = document.createElement("td");
      td.textContent = fmtCell(headers[i], v);
      td.dataset.sort = typeof v === "number" ? v : String(v ?? "");
      if (typeof v === "number") td.className = "num";
      else if (typeof v === "string" && looksLikeIndicator(v)) td.className = "ioc";
      if (typeof v === "string") td.classList.add(v.length > 40 ? "long" : "short");
      r.append(td);
    });
    tbody.append(r);
  }
  t.append(thead, tbody);
  scroller.append(t);
  wrap.append(scroller);
  if (rows.length > ROW_LIMIT) {
    const note = el("p", "truncnote");
    note.textContent = `Showing the first ${ROW_LIMIT.toLocaleString()} of ${rows.length.toLocaleString()} rows. Download the JSON for everything.`;
    wrap.append(note);
  }
  return wrap;
}

function sortTable(t, col, th) {
  const dir = th.getAttribute("aria-sort") === "descending" ? "ascending" : "descending";
  t.querySelectorAll("th").forEach((h) => h.removeAttribute("aria-sort"));
  th.setAttribute("aria-sort", dir);
  const rows = [...t.tBodies[0].rows];
  rows.sort((a, b) => {
    const x = a.cells[col]?.dataset.sort ?? "", y = b.cells[col]?.dataset.sort ?? "";
    const nx = parseFloat(x), ny = parseFloat(y);
    const cmp = !Number.isNaN(nx) && !Number.isNaN(ny) && String(nx) === x && String(ny) === y ? nx - ny : x.localeCompare(y, undefined, { numeric: true });
    return dir === "ascending" ? cmp : -cmp;
  });
  t.tBodies[0].append(...rows);
}

function pre(v) {
  const p = document.createElement("pre");
  p.textContent = JSON.stringify(v, null, 2);
  return p;
}

/* ---------- export ---------- */

function stem() {
  return (state.capture?.name || "capture").replace(/\.[^.]+$/, "");
}

function exportRecord(name, result, params) {
  return JSON.stringify(
    {
      tool: "nthunt web analyzer",
      detector: name,
      capture: state.capture?.name,
      packets: state.capture?.packets,
      settings: params,
      generated_utc: new Date().toISOString(),
      result,
    },
    null,
    2
  );
}

function downloadAll() {
  const all = {};
  for (const [name, r] of state.results) if (r.payload.status === "ok") all[name] = { settings: r.params, result: r.payload.result };
  download(
    `${stem()}-nthunt.json`,
    JSON.stringify({ tool: "nthunt web analyzer", capture: state.capture?.name, packets: state.capture?.packets, generated_utc: new Date().toISOString(), detectors: all }, null, 2)
  );
}

function download(filename, text) {
  const url = URL.createObjectURL(new Blob([text], { type: "application/json" }));
  const a = Object.assign(document.createElement("a"), { href: url, download: filename });
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function toMarkdown(name, result, params) {
  const df = $("defang").checked ? defang : (s) => s;
  const cell = (k, v) => df(fmtCell(k, v)).replace(/\|/g, "\\|").replace(/\n/g, " ");
  const mdTable = (headers, rows) =>
    [`| ${headers.join(" | ")} |`, `|${headers.map(() => "---").join("|")}|`, ...rows.map((r) => `| ${r.map((v, i) => cell(headers[i], v)).join(" | ")} |`)].join("\n");
  const settings = Object.entries(params).map(([k, v]) => `${k}=${v}`).join(", ") || "defaults";
  const lines = [
    `### ${LABELS[name] || titleCase(name)}`,
    "",
    `Command: \`python -m nthunt ${name} ${state.capture?.name}\` (run in the web analyzer)  `,
    `Settings: ${settings}  `,
  ];

  const section = (v) => {
    if (Array.isArray(v)) {
      if (!v.length) return "_No findings._";
      if (v.every(isPlainObj)) {
        const cols = [...new Set(v.flatMap(Object.keys))];
        return mdTable(cols, v.map((o) => cols.map((c) => o[c])));
      }
      if (v.every((x) => Array.isArray(x) && x.length === 2)) return mdTable(["Value", "Count"], v);
      if (v.every(isScalar)) return mdTable(["Value"], v.map((x) => [x]));
    }
    if (isPlainObj(v) && Object.values(v).every(isScalar)) return mdTable(["Key", "Value"], Object.entries(v));
    return "```json\n" + df(JSON.stringify(v, null, 2)) + "\n```";
  };

  if (Array.isArray(result)) {
    lines.push(`Findings: ${result.length}`, "", section(result));
  } else if (isPlainObj(result)) {
    const scalars = Object.entries(result).filter(([, v]) => isScalar(v));
    lines.push("");
    if (scalars.length) lines.push(mdTable(["Field", "Value"], scalars), "");
    for (const [k, v] of Object.entries(result).filter(([, v]) => !isScalar(v))) lines.push(`**${titleCase(k)}**`, "", section(v), "");
  } else {
    lines.push("", section(result));
  }
  return lines.join("\n").trim() + "\n";
}

// Defang the way the case reports do: 192.0.2[.]10, evil[.]com, hxxp://
function defang(s) {
  return String(s)
    .replace(/\bhttp(s?):\/\//gi, "hxxp$1://")
    .replace(/\b(\d{1,3}\.\d{1,3}\.\d{1,3})\.(\d{1,3})\b/g, "$1[.]$2")
    .replace(/\b((?:[a-z0-9-]+\.)*[a-z0-9-]*[a-z][a-z0-9-]*)\.([a-z]{2,24})\b(?!\()/gi, "$1[.]$2");
}

/* ---------- helpers ---------- */

function el(tag, cls) {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  return n;
}
function button(label, onClick) {
  const b = el("button", "btn btn--quiet");
  b.type = "button";
  b.textContent = label;
  b.addEventListener("click", onClick);
  return b;
}
function esc(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
}
const ACRONYMS = { ip: "IP", ips: "IPs", dns: "DNS", tcp: "TCP", udp: "UDP", icmp: "ICMP", cv: "CV", id: "ID", ttl: "TTL", url: "URL", c2: "C2", mac: "MAC", tls: "TLS", http: "HTTP", nxdomain: "NXDOMAIN" };
function titleCase(s) {
  const t = String(s).replace(/[_-]+/g, " ").trim().split(/\s+/).map((w) => ACRONYMS[w.toLowerCase()] || w).join(" ");
  return t.charAt(0).toUpperCase() + t.slice(1);
}
function looksLikeIndicator(s) {
  return /^(\d{1,3}\.){3}\d{1,3}(:\d+)?$/.test(s) || /^[0-9a-f:]+:[0-9a-f:]*$/i.test(s) || /^([a-z0-9-]+\.)+[a-z]{2,}\.?$/i.test(s) || / → /.test(s);
}
function fmtCell(key, v) {
  if (v === null || v === undefined) return "";
  if (typeof v === "number") {
    // Epoch timestamps (as Scapy gives them) become readable UTC times.
    if (/time|first|last|start|end|seen/i.test(key) && v > 946684800 && v < 4102444800) return fmtTime(v);
    return Number.isInteger(v) ? v.toLocaleString() : v.toFixed(3).replace(/0+$/, "").replace(/\.$/, "");
  }
  return String(v);
}
function fmtTime(sec, short = false) {
  const iso = new Date(sec * 1000).toISOString();
  return short ? iso.slice(11, 19) : iso.slice(0, 19).replace("T", " ");
}
function fmtDuration(s) {
  if (s < 60) return `${s.toFixed(s < 10 ? 1 : 0)} s`;
  if (s < 3600) return `${Math.floor(s / 60)} min ${Math.round(s % 60)} s`;
  return `${Math.floor(s / 3600)} h ${Math.round((s % 3600) / 60)} min`;
}
function fmtBytes(b) {
  if (b < 1024) return `${b} B`;
  if (b < 1048576) return `${(b / 1024).toFixed(0)} KB`;
  return `${(b / 1048576).toFixed(1)} MB`;
}
function showNotice(msg) {
  const box = $("loadError");
  box.className = "notice notice--info";
  box.textContent = msg;
  box.hidden = false;
}
function clearNotice() {
  const box = $("loadError");
  box.className = "notice notice--error";
  box.hidden = true;
}
async function copyText(text, okMsg) {
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    const ta = Object.assign(document.createElement("textarea"), { value: text });
    document.body.append(ta);
    ta.select();
    document.execCommand("copy");
    ta.remove();
  }
  toast(okMsg);
}
let toastTimer;
function toast(msg) {
  let t = document.querySelector(".toast");
  if (!t) {
    t = el("div", "toast");
    t.setAttribute("role", "status");
    document.body.append(t);
  }
  t.textContent = msg;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.remove(), 3500);
}

// When hosted at <user>.github.io/<repo>/, link back to the repository.
function linkRepo() {
  const m = location.hostname.match(/^([^.]+)\.github\.io$/i);
  if (!m) return;
  const repo = location.pathname.split("/").filter(Boolean)[0];
  const base = repo ? `https://github.com/${m[1]}/${repo}` : `https://github.com/${m[1]}`;
  Object.assign($("repoLink"), { href: base, hidden: false });
  if (repo) Object.assign($("methodLink"), { href: `${base}/blob/main/docs/methodology.md`, hidden: false });
}

/* ---------- wire up ---------- */

function init() {
  linkRepo();
  const drop = $("drop"), input = $("file");
  drop.addEventListener("click", () => !state.busy && input.click());
  drop.addEventListener("keydown", (e) => (e.key === "Enter" || e.key === " ") && (e.preventDefault(), input.click()));
  input.addEventListener("change", () => { acceptFile(input.files[0]); input.value = ""; });
  ["dragenter", "dragover"].forEach((t) => drop.addEventListener(t, (e) => { e.preventDefault(); drop.classList.add("is-over"); }));
  ["dragleave", "drop"].forEach((t) => drop.addEventListener(t, (e) => { e.preventDefault(); drop.classList.remove("is-over"); }));
  drop.addEventListener("drop", (e) => acceptFile(e.dataTransfer.files[0]));
  // Dropping a file anywhere else on the page shouldn't navigate away from it.
  window.addEventListener("dragover", (e) => e.preventDefault());
  window.addEventListener("drop", (e) => { e.preventDefault(); if (e.target.closest && !e.target.closest("#drop")) acceptFile(e.dataTransfer.files[0]); });

  $("sampleBtn").addEventListener("click", loadSample);
  $("replaceBtn").addEventListener("click", () => input.click());
  $("runBtn").addEventListener("click", runSelected);
  $("downloadAll").addEventListener("click", downloadAll);
  $("demoBtn").addEventListener("click", startDemo);
  setupInstall();
  startEngine();
  // A link ending in ?demo (e.g. on a resume) starts the demo right away.
  if (new URLSearchParams(location.search).has("demo")) startDemo();
}

init();
