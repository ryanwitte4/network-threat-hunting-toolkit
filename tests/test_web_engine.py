"""Tests for the web analyzer's bridge code (web/engine.py)."""

import importlib.util
import json
from pathlib import Path

from nthunt import beacon

spec = importlib.util.spec_from_file_location("engine", Path(__file__).parents[1] / "web" / "engine.py")
engine = importlib.util.module_from_spec(spec)
spec.loader.exec_module(engine)


def test_stub_detection():
    def built(packets):
        """Docstring."""
        return []

    assert engine._is_stub(built) is False
    # Flips to False automatically once find_beacons is implemented.
    source_is_stub = "raise NotImplementedError" in Path(beacon.__file__).read_text()
    assert engine._is_stub(beacon.find_beacons) is source_is_stub


def test_results_become_json_safe():
    out = engine._plain({("10.0.0.1", "10.0.0.2", 443): 5, "hosts": {"b", "a"}, "raw": b"x"})
    assert out == {"10.0.0.1 → 10.0.0.2 → 443": 5, "hosts": ["a", "b"], "raw": "x"}
    json.dumps(out)


def test_detectors_are_described():
    from nthunt.cli import COMMANDS

    info = engine._describe("beacon", COMMANDS["beacon"])
    assert [p["name"] for p in info["params"]] == ["min_connections", "max_jitter", "min_interval_seconds"]
    assert info["file"] == "nthunt/beacon.py"
