"""Bridge between the web analyzer and the nthunt package.

Runs inside Pyodide (Python compiled to WebAssembly) in a Web Worker.
It does not contain any detection logic of its own: it loads the real
`nthunt` package, discovers its commands from `nthunt.cli.COMMANDS`, and
calls them exactly as the CLI does. Anything you build in nthunt/ shows
up in the browser automatically.
"""

import ast
import inspect
import json
import logging
import socket
import textwrap
from decimal import Decimal

PACKETS = []
CAPTURE = {}


def _patch_runtime():
    """Make Scapy importable under Pyodide.

    Pyodide's socket module reports IPv6 as unavailable and its inet_pton
    rejects AF_INET6. Scapy has pure-Python fallbacks for both, so we point
    it at those. Only parsing is needed here; nothing touches the network.
    """
    socket.has_ipv6 = True
    for name in ("inet_pton", "inet_ntop"):
        if hasattr(socket, name):
            delattr(socket, name)


def boot():
    _patch_runtime()
    scapy_log = logging.getLogger("scapy")
    scapy_log.setLevel(logging.CRITICAL + 1)  # hide "I/O not supported" noise
    import scapy.all  # noqa: F401  (pre-load layers once)
    scapy_log.setLevel(logging.WARNING)

    import nthunt
    from nthunt.cli import COMMANDS

    detectors = [_describe(name, func) for name, func in COMMANDS.items()]
    return json.dumps({"version": getattr(nthunt, "__version__", "?"), "detectors": detectors})


def _describe(name, func):
    doc = inspect.getdoc(func) or ""
    summary = doc.split("\n\n")[0].replace("\n", " ").strip()
    params = []
    sig = inspect.signature(func)
    for i, p in enumerate(sig.parameters.values()):
        if i == 0:
            continue  # the packet list
        if p.default is inspect.Parameter.empty:
            continue
        if isinstance(p.default, bool):
            kind = "bool"
        elif isinstance(p.default, int):
            kind = "int"
        elif isinstance(p.default, float):
            kind = "float"
        elif isinstance(p.default, str):
            kind = "str"
        else:
            continue
        params.append({"name": p.name, "default": p.default, "kind": kind})
    return {
        "name": name,
        "function": f"{func.__module__}.{func.__name__}",
        "file": "/".join(inspect.getsourcefile(func).split("/")[-2:]),
        "summary": summary,
        "params": params,
        "built": not _is_stub(func),
    }


def _is_stub(func):
    """True when the function body is only a docstring + raise NotImplementedError."""
    try:
        tree = ast.parse(textwrap.dedent(inspect.getsource(func)))
    except (OSError, SyntaxError):
        return False
    body = tree.body[0].body
    if body and isinstance(body[0], ast.Expr) and isinstance(getattr(body[0], "value", None), ast.Constant):
        body = body[1:]
    if len(body) != 1 or not isinstance(body[0], ast.Raise):
        return False
    exc = body[0].exc
    target = exc.func if isinstance(exc, ast.Call) else exc
    return isinstance(target, ast.Name) and target.id == "NotImplementedError"


def load_capture(path, progress=None, buckets=90):
    """Read the capture with nthunt's own loader and keep the packets in memory."""
    from nthunt.pcap_loader import iter_packets

    packets, times = [], []
    for pkt in iter_packets(path):
        packets.append(pkt)
        times.append(float(pkt.time))
        if progress and len(packets) % 2000 == 0:
            progress(len(packets))

    # Only replace the previous capture once the new one parsed cleanly.
    PACKETS[:] = packets
    CAPTURE.clear()
    CAPTURE["packets"] = len(PACKETS)
    if times:
        start, end = min(times), max(times)
        span = max(end - start, 1e-9)
        counts = [0] * buckets
        for t in times:
            counts[min(int((t - start) / span * buckets), buckets - 1)] += 1
        CAPTURE.update(start=start, end=end, histogram=counts)
    return json.dumps(CAPTURE)


def run(name, params_json):
    """Call one nthunt command on the loaded packets and return JSON."""
    from nthunt.cli import COMMANDS

    params = json.loads(params_json)
    func = COMMANDS[name]
    try:
        result = func(list(PACKETS), **params)
    except NotImplementedError as exc:
        return json.dumps({"status": "not_built", "message": str(exc) or f"{name} is not built yet"})
    except Exception as exc:  # show the traceback so it can be debugged
        import traceback

        return json.dumps({
            "status": "error",
            "message": f"{type(exc).__name__}: {exc}",
            "traceback": traceback.format_exc(),
        })
    return json.dumps({"status": "ok", "result": _plain(result)})


def _plain(obj):
    """Convert results into JSON-safe values (what the CLI's default=str would print)."""
    if isinstance(obj, dict):
        return {_key(k): _plain(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_plain(v) for v in obj]
    if isinstance(obj, (set, frozenset)):
        return sorted((_plain(v) for v in obj), key=str)
    if isinstance(obj, bool) or obj is None or isinstance(obj, (int, str)):
        return obj
    if isinstance(obj, float):
        return obj if obj == obj and abs(obj) != float("inf") else str(obj)
    if isinstance(obj, Decimal):
        return float(obj)
    if isinstance(obj, bytes):
        return obj.decode("utf-8", "replace")
    try:
        return float(obj)  # Scapy's EDecimal timestamps
    except (TypeError, ValueError):
        return str(obj)


def _key(k):
    if isinstance(k, str):
        return k
    if isinstance(k, tuple):
        return " → ".join(str(_plain(x)) for x in k)
    return str(_plain(k))
