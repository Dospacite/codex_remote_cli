from __future__ import annotations

import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from codex_remote_cli.__main__ import (
    BridgeConfig,
    _validate_relay_url,
    build_parser,
    resolve_app_server_command,
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


class AppServerResolutionTests(unittest.TestCase):
    def test_prefers_binary_found_on_path(self) -> None:
        with mock.patch("codex_remote_cli.__main__.shutil.which", return_value="/usr/local/bin/codex"):
            resolved = resolve_app_server_command("codex app-server")
        self.assertEqual(resolved, ["/usr/local/bin/codex", "app-server"])

    def test_uses_cwd_when_binary_is_not_on_path(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            script = Path(tempdir) / "app-server"
            script.write_text("#!/bin/sh\n", encoding="utf-8")
            with mock.patch("codex_remote_cli.__main__.shutil.which", return_value=None):
                resolved = resolve_app_server_command("app-server", cwd=tempdir)
        self.assertEqual(resolved, [str(script.resolve())])

    def test_accepts_explicit_relative_path(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            current = Path.cwd()
            script = Path(tempdir) / "bin" / "app-server"
            script.parent.mkdir(parents=True, exist_ok=True)
            script.write_text("#!/bin/sh\n", encoding="utf-8")
            try:
                os.chdir(tempdir)
                resolved = resolve_app_server_command("bin/app-server")
            finally:
                os.chdir(current)
        self.assertEqual(resolved, [str(script.resolve())])

    def test_reports_clear_error_when_binary_cannot_be_found(self) -> None:
        with mock.patch("codex_remote_cli.__main__.shutil.which", return_value=None):
            with self.assertRaises(FileNotFoundError) as context:
                resolve_app_server_command("codex app-server", cwd="/tmp/missing-app-server")
        self.assertIn("Set --app-server-bin or CODEX_REMOTE_APP_SERVER_BIN", str(context.exception))

    def test_rejects_empty_command(self) -> None:
        with self.assertRaises(ValueError):
            resolve_app_server_command(" ")


class ParserTests(unittest.TestCase):
    def test_app_server_bin_defaults_from_environment(self) -> None:
        with mock.patch.dict("os.environ", {"CODEX_REMOTE_APP_SERVER_BIN": "/tmp/app-server"}, clear=False):
            parser = build_parser()
            args = parser.parse_args(["serve"])
        self.assertEqual(args.app_server_bin, "/tmp/app-server")
