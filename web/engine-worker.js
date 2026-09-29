/* Runs Python (Pyodide) off the main thread so the page never freezes.
 * Messages in:  {type:"boot", siteBase} | {type:"load", name, bytes} | {type:"run", id, name, params}
 * Messages out: {type:"status", text} | {type:"ready", info} | {type:"loaded", capture}
 *               {type:"progress", packets} | {type:"result", id, payload} | {type:"fatal", message}
 */
const PYODIDE_VERSION = "0.27.2";
const PYODIDE_BASE = `https://cdn.jsdelivr.net/pyodide/v${PYODIDE_VERSION}/full/`;
// Scapy is pure Python, so the normal PyPI wheel runs unchanged in the browser.
const SCAPY_WHEEL =
  "https://files.pythonhosted.org/packages/4b/34/8695b43af99d0c796e4b7933a0d7df8925f43a8abdd0ff0f6297beb4de3a/scapy-2.6.1-py3-none-any.whl";
// Used only if nthunt/manifest.json is missing (e.g. previewing locally).
const FALLBACK_MODULES = ["__init__.py", "__main__.py", "cli.py", "pcap_loader.py", "packet_utils.py", "summary.py", "beacon.py", "dns_anomaly.py", "scan_detect.py"];

let py = null;
let engine = null;

const say = (text) => postMessage({ type: "status", text });

async function fetchText(url) {
  const r = await fetch(url, { cache: "no-cache" });
  if (!r.ok) throw new Error(`${r.status} ${url}`);
  return r.text();
}

// The deployed site has nthunt/ beside index.html; a local preview served
// from the repo root has it one level up. Try both.
async function locatePackage(siteBase) {
  for (const base of [new URL("nthunt/", siteBase), new URL("../nthunt/", siteBase)]) {
    try {
      const init = await fetch(new URL("__init__.py", base), { cache: "no-cache" });
      if (!init.ok) continue;
      let files = FALLBACK_MODULES;
      try {
        files = JSON.parse(await fetchText(new URL("manifest.json", base)));
      } catch (_) { /* local preview: use fallback list */ }
      return { base, files };
    } catch (_) { /* try next */ }
  }
  throw new Error("Could not find the nthunt package next to this page.");
}

async function boot(siteBase) {
  say("Downloading the Python runtime");
  importScripts(PYODIDE_BASE + "pyodide.js");
  py = await loadPyodide({ indexURL: PYODIDE_BASE, stdout: () => {}, stderr: (s) => console.debug(s) });

  say("Installing Scapy");
  await py.loadPackage(SCAPY_WHEEL, { messageCallback: () => {} });

  say("Loading the nthunt toolkit");
  const { base, files } = await locatePackage(siteBase);
  py.FS.mkdirTree("/home/pyodide/nthunt");
  await Promise.all(
    files.map(async (f) => py.FS.writeFile(`/home/pyodide/nthunt/${f}`, await fetchText(new URL(f, base))))
  );
  py.FS.writeFile("/home/pyodide/nthunt_web_engine.py", await fetchText(new URL("engine.py", siteBase)));

  say("Starting the detectors");
  engine = py.pyimport("nthunt_web_engine");
  const info = JSON.parse(engine.boot());
  postMessage({ type: "ready", info });
}

function load(name, bytes) {
  const ext = /\.pcapng$/i.test(name) ? ".pcapng" : ".pcap";
  const path = "/tmp/capture" + ext;
  for (const old of ["/tmp/capture.pcap", "/tmp/capture.pcapng"]) {
    try { py.FS.unlink(old); } catch (_) {}
  }
  py.FS.writeFile(path, new Uint8Array(bytes));
  const capture = JSON.parse(engine.load_capture(path, (n) => postMessage({ type: "progress", packets: n })));
  py.FS.unlink(path); // the parsed packets stay in memory; the raw file isn't needed
  postMessage({ type: "loaded", capture });
}

function run(id, name, params) {
  const started = performance.now();
  const payload = JSON.parse(engine.run(name, JSON.stringify(params)));
  payload.seconds = (performance.now() - started) / 1000;
  postMessage({ type: "result", id, payload });
}

onmessage = async ({ data }) => {
  try {
    if (data.type === "boot") await boot(data.siteBase);
    else if (data.type === "load") load(data.name, data.bytes);
    else if (data.type === "run") run(data.id, data.name, data.params);
  } catch (err) {
    // Python errors arrive with the whole traceback; the last line says what went wrong.
    const full = String(err && err.message ? err.message : err).trim();
    const message = full.split("\n").filter(Boolean).pop() || full;
    postMessage({ type: "fatal", stage: data.type, message, detail: full });
  }
};
