"""Import smoke test. Detector tests live in test_detectors.py."""

import nthunt
from nthunt import beacon, cli, dns_anomaly, scan_detect, summary  # noqa: F401


def test_version():
    assert nthunt.__version__

