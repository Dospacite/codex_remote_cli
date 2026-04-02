from __future__ import annotations

import stat
import tempfile
import unittest
from pathlib import Path

from codex_remote_cli.__main__ import (
    BridgeConfig,
    _validate_relay_url,
    render_pairing_qr,
)


class RelayUrlValidationTests(unittest.TestCase):
    def test_https_is_allowed(self) -> None:
        _validate_relay_url("https://relay.example.com")

    def test_local_http_is_allowed(self) -> None:
        _validate_relay_url("http://127.0.0.1:8787")

    def test_remote_http_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            _validate_relay_url("http://relay.example.com")


class BridgeConfigTests(unittest.TestCase):
    def test_save_restricts_permissions(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            path = Path(tempdir) / "config.json"
            config = BridgeConfig.create(
                relay_url="https://relay.example.com",
                bridge_label="workstation",
            )
            config.save(path)

            mode = stat.S_IMODE(path.stat().st_mode)
            self.assertEqual(mode, 0o600)


class PairingQrTests(unittest.TestCase):
    def test_render_pairing_qr_returns_ascii_content(self) -> None:
        rendered = render_pairing_qr("crp1.example")
        self.assertTrue(rendered)
        self.assertIn("\n", rendered)
