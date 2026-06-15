from __future__ import annotations

import json

import pytest


def test_rust_kernel_bridge_round_trip() -> None:
    rygnal_kernel = pytest.importorskip("rygnal_kernel")

    result = rygnal_kernel.verify_bridge("pytest handshake")

    assert result == ("[Rust Kernel]: Connection secure. Received payload -> pytest handshake")


def test_rust_kernel_evaluates_patch_risk() -> None:
    rygnal_kernel = pytest.importorskip("rygnal_kernel")

    payload = {
        "sha256": "abc123xyz",
        "changes": [
            {"path": "src/main.py", "kind": "modified"},
            {"path": "config/db.yml", "kind": "deleted"},
        ],
    }

    result = rygnal_kernel.evaluate_patch_risk(json.dumps(payload))

    assert result == (
        "Kernel evaluated patch [abc123xyz]. Analyzed 2 files. High-risk deletions detected: 1"
    )


def test_rust_kernel_rejects_invalid_patch_json() -> None:
    rygnal_kernel = pytest.importorskip("rygnal_kernel")

    bad_payload = '{"missing_sha": true, "garbage_data": [1, 2, 3]}'

    with pytest.raises(ValueError, match="Rust safety kernel failed to parse JSON"):
        rygnal_kernel.evaluate_patch_risk(bad_payload)
