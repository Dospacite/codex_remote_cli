from __future__ import annotations

import asyncio
import base64
import json
import os
import socket
import stat
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
from pathlib import Path

import aiohttp
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def _b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64d(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * ((4 - len(value) % 4) % 4))


def _canon(data: dict[str, object]) -> bytes:
    return json.dumps(data, separators=(",", ":"), sort_keys=True).encode()


def _nonce(prefix: bytes, counter: int) -> bytes:
    return prefix + counter.to_bytes(8, "big")


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


class _RelayClient:
    def __init__(self, *, relay_url: str, pairing_code: str) -> None:
        self._relay_url = relay_url.rstrip("/")
        self._pairing_code = pairing_code
        payload = json.loads(_b64d(pairing_code.split(".", 1)[1]))
        self.device_id = str(payload["deviceId"])
        self._client_private = ed25519.Ed25519PrivateKey.generate()
        self._session_private: x25519.X25519PrivateKey | None = None
        self._cipher: ChaCha20Poly1305 | None = None
        self._session_id: str | None = None
        self._send_counter = 0
        self._receive_counter = 0
        self.notifications: list[dict[str, object]] = []
        self.server_requests: list[dict[str, object]] = []
        self._session: aiohttp.ClientSession | None = None
        self._ws: aiohttp.ClientWebSocketResponse | None = None
        self._bridge_signing_public_key: str | None = None

    async def connect(self) -> None:
        public_key = self._client_private.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        self._session = aiohttp.ClientSession()
        async with self._session.post(
            f"{self._relay_url}/api/v1/device/claim",
            json={
                "pairingCode": self._pairing_code,
                "clientLabel": "Integration Test Client",
                "clientSigningPublicKey": _b64e(public_key),
            },
        ) as response:
            body = await response.text()
            if response.status != 200:
                raise AssertionError(f"claim failed: {response.status} {body}")
            claim = json.loads(body)
        self._bridge_signing_public_key = str(claim["bridgeSigningPublicKey"])
        self._ws = await self._session.ws_connect(f"{self._relay_url}/ws", heartbeat=20)
        challenge = await self._ws.receive_json()
        auth_nonce = _b64e(b"relay-client-auth")
        auth_timestamp = int(time.time())
        self._session_private = x25519.X25519PrivateKey.generate()
        session_public = self._session_private.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        session_nonce = _b64e(b"relay-client-session")
        signed_at = int(time.time())
        auth_sig = self._client_private.sign(
            _canon(
                {
                    "authNonce": auth_nonce,
                    "authTimestamp": auth_timestamp,
                    "challenge": challenge["challenge"],
                    "connectionId": challenge["connectionId"],
                    "deviceId": self.device_id,
                    "role": "client",
                    "type": "codex-remote-auth-v1",
                }
            )
        )
        bundle_sig = self._client_private.sign(
            _canon(
                {
                    "deviceId": self.device_id,
                    "role": "client",
                    "sessionNonce": session_nonce,
                    "sessionPublicKey": _b64e(session_public),
                    "signedAt": signed_at,
                    "type": "codex-remote-session-bundle-v1",
                }
            )
        )
        await self._ws.send_json(
            {
                "type": "authenticate",
                "deviceId": self.device_id,
                "role": "client",
                "authNonce": auth_nonce,
                "authTimestamp": auth_timestamp,
                "authSignature": _b64e(auth_sig),
                "sessionBundle": {
                    "sessionNonce": session_nonce,
                    "sessionPublicKey": _b64e(session_public),
                    "signedAt": signed_at,
                    "signature": _b64e(bundle_sig),
                },
            }
        )
        await self._expect_message_type("authenticated")
        opened = await self._expect_message_type("session_open")
        peer_bundle = opened["peerSessionBundle"]
        ed25519.Ed25519PublicKey.from_public_bytes(
            _b64d(self._bridge_signing_public_key or "")
        ).verify(
            _b64d(str(peer_bundle["signature"])),
            _canon(
                {
                    "deviceId": self.device_id,
                    "role": "bridge",
                    "sessionNonce": peer_bundle["sessionNonce"],
                    "sessionPublicKey": peer_bundle["sessionPublicKey"],
                    "signedAt": peer_bundle["signedAt"],
                    "type": "codex-remote-session-bundle-v1",
                }
            ),
        )
        shared = self._session_private.exchange(
            x25519.X25519PublicKey.from_public_bytes(
                _b64d(str(peer_bundle["sessionPublicKey"]))
            )
        )
        digest = hashes.Hash(hashes.SHA256())
        for value in sorted([session_nonce, str(peer_bundle["sessionNonce"])]):
            digest.update(value.encode())
        key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=digest.finalize(),
            info=self.device_id.encode(),
        ).derive(shared)
        self._cipher = ChaCha20Poly1305(key)
        self._session_id = str(opened["sessionId"])

    async def close(self) -> None:
        if self._ws is not None:
            await self._ws.close()
        if self._session is not None:
            await self._session.close()

    async def request(self, request_id: int, method: str, params: dict[str, object]) -> dict[str, object]:
        await self.send_json({"id": request_id, "method": method, "params": params})
        while True:
            message = await self.receive_json()
            if message.get("id") == request_id:
                if message.get("error") is not None:
                    raise AssertionError(f"JSON-RPC error for {method}: {message['error']}")
                return message
            if "method" in message and "id" in message:
                self.server_requests.append(message)
                await self.send_json(
                    {
                        "id": message["id"],
                        "result": {
                            "approved": True,
                            "handledBy": "relay-integration-test",
                        },
                    }
                )
                continue
            self.notifications.append(message)

    async def send_json(self, payload: dict[str, object]) -> None:
        assert self._ws is not None
        assert self._cipher is not None
        assert self._session_id is not None
        counter = self._send_counter
        self._send_counter += 1
        plaintext = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
        aad = _canon(
            {
                "counter": counter,
                "deviceId": self.device_id,
                "sessionId": self._session_id,
                "type": "relay-frame-v1",
            }
        )
        ciphertext = self._cipher.encrypt(_nonce(b"CLNT", counter), plaintext, aad)
        await self._ws.send_json(
            {
                "type": "relay_frame",
                "sessionId": self._session_id,
                "counter": counter,
                "ciphertext": _b64e(ciphertext),
            }
        )

    async def receive_json(self) -> dict[str, object]:
        assert self._ws is not None
        assert self._cipher is not None
        assert self._session_id is not None
        while True:
            message = await self._ws.receive_json(timeout=10)
            if message.get("type") == "close_session":
                raise AssertionError(f"relay closed session unexpectedly: {message}")
            if message.get("type") != "relay_frame":
                return message
            counter = int(message["counter"])
            if counter != self._receive_counter:
                raise AssertionError(
                    f"unexpected relay counter: expected {self._receive_counter}, got {counter}"
                )
            self._receive_counter += 1
            aad = _canon(
                {
                    "counter": counter,
                    "deviceId": self.device_id,
                    "sessionId": self._session_id,
                    "type": "relay-frame-v1",
                }
            )
            plaintext = self._cipher.decrypt(
                _nonce(b"BRDG", counter),
                _b64d(str(message["ciphertext"])),
                aad,
            )
            return json.loads(plaintext)

    async def _expect_message_type(self, message_type: str) -> dict[str, object]:
        assert self._ws is not None
        while True:
            payload = await self._ws.receive_json(timeout=10)
            if payload.get("type") == message_type:
                return payload


class RelayIntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self._tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self._tempdir.cleanup)
        self.temp_path = Path(self._tempdir.name)
        self.workspace_path = self.temp_path / "workspace"
        self.workspace_path.mkdir(parents=True, exist_ok=True)
        (self.workspace_path / "README.md").write_text(
            "hello from relay workspace\n",
            encoding="utf-8",
        )
        self._server_process: asyncio.subprocess.Process | None = None
        self._cli_process: asyncio.subprocess.Process | None = None
        self._relay_port = _free_port()
        self._app_server_port = _free_port()
        self._config_path = self.temp_path / "bridge-config.json"
        self._app_server_log = self.temp_path / "fake-app-server-log.jsonl"
        self._install_fake_app_server()
        await self._start_relay_server()
        await self._start_bridge_cli()

    async def asyncTearDown(self) -> None:
        await self._terminate_process(self._cli_process)
        await self._terminate_process(self._server_process)

    async def test_bidirectional_codex_app_server_messages_flow_through_relay(self) -> None:
        pairing_code = await self._wait_for_pairing_code()
        client = _RelayClient(
            relay_url=f"http://127.0.0.1:{self._relay_port}",
            pairing_code=pairing_code,
        )
        await client.connect()
        self.addAsyncCleanup(client.close)

        initialize = await client.request(
            1,
            "initialize",
            {
                "clientInfo": {
                    "name": "relay_integration_test",
                    "title": "Relay Integration Test",
                    "version": "1.0.0",
                }
            },
        )
        self.assertEqual(initialize["result"]["codexHome"], "/tmp/fake-codex-home")

        thread_start = await client.request(2, "thread/start", {})
        self.assertEqual(thread_start["result"]["thread"]["id"], "thread-relay-1")

        fs_read = await client.request(
            3,
            "fs/readDirectory",
            {"path": str(self.workspace_path)},
        )
        self.assertEqual(fs_read["result"]["entries"][0]["fileName"], "README.md")

        fs_read_file = await client.request(
            31,
            "fs/readFile",
            {"path": str(self.workspace_path / "README.md")},
        )
        self.assertEqual(
            base64.b64decode(str(fs_read_file["result"]["dataBase64"])).decode("utf-8"),
            "hello from relay workspace\n",
        )

        download_start = await client.request(
            32,
            "bridge/download/start",
            {"path": str(self.workspace_path / "README.md")},
        )
        async with aiohttp.ClientSession() as http_session:
            async with http_session.get(str(download_start["result"]["url"])) as response:
                self.assertEqual(response.status, 200)
                self.assertEqual(
                    await response.text(),
                    "hello from relay workspace\n",
                )

        turn_start = await client.request(
            4,
            "turn/start",
            {
                "threadId": "thread-relay-1",
                "input": [{"type": "text", "text": "Relay integration test"}],
            },
        )
        self.assertEqual(turn_start["result"]["turn"]["status"], "completed")

        command_exec = await client.request(
            5,
            "command/exec",
            {
                "processId": "proc-buffered",
                "command": ["/bin/echo", "through-relay"],
                "streamStdoutStderr": True,
            },
        )
        self.assertEqual(command_exec["result"]["exitCode"], 0)

        command_write = await client.request(
            6,
            "command/exec/write",
            {
                "processId": "proc-interactive",
                "deltaBase64": _b64e(b"typed-from-client\n"),
                "closeStdin": True,
            },
        )
        self.assertTrue(command_write["result"]["accepted"])

        notification_methods = [str(message.get("method")) for message in client.notifications]
        self.assertIn("thread/started", notification_methods)
        self.assertIn("turn/outputDelta", notification_methods)
        self.assertIn("turn/completed", notification_methods)
        self.assertIn("command/exec/outputDelta", notification_methods)

        server_request_methods = [str(message.get("method")) for message in client.server_requests]
        self.assertIn("permissions/request", server_request_methods)

        logged_messages = [
            json.loads(line)
            for line in self._app_server_log.read_text("utf-8").splitlines()
            if line.strip()
        ]
        received_methods = [
            str(item["payload"].get("method"))
            for item in logged_messages
            if item["kind"] == "received" and "method" in item["payload"]
        ]
        self.assertIn("initialize", received_methods)
        self.assertIn("thread/start", received_methods)
        self.assertIn("turn/start", received_methods)
        self.assertIn("command/exec", received_methods)
        self.assertIn("command/exec/write", received_methods)
        self.assertNotIn("fs/readDirectory", received_methods)
        self.assertNotIn("fs/readFile", received_methods)
        self.assertNotIn("bridge/download/start", received_methods)

        client_response = next(
            item["payload"]
            for item in logged_messages
            if item["kind"] == "received"
            and item["payload"].get("id") == 9001
            and "result" in item["payload"]
        )
        self.assertEqual(client_response["result"]["handledBy"], "relay-integration-test")

    def _install_fake_app_server(self) -> None:
        script_path = self.temp_path / "app-server"
        script_path.write_text(
            textwrap.dedent(
                f"""\
                #!/usr/bin/env python3
                import argparse
                import asyncio
                import base64
                import json
                import os
                from pathlib import Path
                from urllib.parse import urlparse

                from aiohttp import web

                LOG_PATH = Path({str(self._app_server_log)!r})
                SERVER_REQUEST_ID = 9001

                def log(kind, payload):
                    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
                    with LOG_PATH.open("a", encoding="utf-8") as handle:
                        handle.write(json.dumps({{"kind": kind, "payload": payload}}, sort_keys=True) + "\\n")

                def parser():
                    parsed = argparse.ArgumentParser()
                    parsed.add_argument("--listen", required=True)
                    parsed.add_argument("--ws-auth")
                    parsed.add_argument("--ws-token-file")
                    return parsed

                async def main():
                    args = parser().parse_args()
                    parsed = urlparse(args.listen)
                    host = parsed.hostname or "127.0.0.1"
                    port = parsed.port or 0
                    token = Path(args.ws_token_file).read_text("utf-8").strip() if args.ws_token_file else ""

                    async def readyz(_request):
                        return web.Response(text="ok")

                    async def ws_handler(request):
                        if token:
                            auth = request.headers.get("Authorization", "")
                            if auth != f"Bearer {{token}}":
                                return web.Response(status=401, text="unauthorized")
                        ws = web.WebSocketResponse(heartbeat=20)
                        await ws.prepare(request)
                        command_writes = {{}}
                        async for message in ws:
                            if message.type != web.WSMsgType.TEXT:
                                continue
                            payload = json.loads(message.data)
                            log("received", payload)
                            if "method" in payload:
                                method = payload["method"]
                                if method == "initialize":
                                    await ws.send_str(json.dumps({{"id": payload["id"], "result": {{"codexHome": "/tmp/fake-codex-home"}}}}, sort_keys=True))
                                elif method == "thread/start":
                                    await ws.send_str(json.dumps({{"method": "thread/started", "params": {{"thread": {{"id": "thread-relay-1"}}, "origin": "app-server"}}}}, sort_keys=True))
                                    await ws.send_str(json.dumps({{"id": SERVER_REQUEST_ID, "method": "permissions/request", "params": {{"kind": "command", "command": ["/bin/echo", "approve"]}}}}, sort_keys=True))
                                    await ws.send_str(json.dumps({{"id": payload["id"], "result": {{"thread": {{"id": "thread-relay-1"}}}}}}, sort_keys=True))
                                elif method == "fs/readDirectory":
                                    await ws.send_str(json.dumps({{"id": payload["id"], "result": {{"entries": [{{"fileName": "WRONG.txt", "isDirectory": False, "isFile": True}}]}}}}, sort_keys=True))
                                elif method == "fs/readFile":
                                    await ws.send_str(json.dumps({{"id": payload["id"], "result": {{"dataBase64": base64.b64encode(b"wrong").decode("ascii")}}}}, sort_keys=True))
                                elif method == "turn/start":
                                    await ws.send_str(json.dumps({{"method": "turn/outputDelta", "params": {{"threadId": "thread-relay-1", "delta": "hello"}}}}, sort_keys=True))
                                    await ws.send_str(json.dumps({{"method": "turn/completed", "params": {{"threadId": "thread-relay-1", "turnId": "turn-relay-1"}}}}, sort_keys=True))
                                    await ws.send_str(json.dumps({{"id": payload["id"], "result": {{"turn": {{"id": "turn-relay-1", "status": "completed"}}}}}}, sort_keys=True))
                                elif method == "command/exec":
                                    process_id = payload["params"]["processId"]
                                    command_writes[process_id] = []
                                    delta = base64.b64encode(b"through-relay\\n").decode("ascii")
                                    await ws.send_str(json.dumps({{"method": "command/exec/outputDelta", "params": {{"processId": process_id, "deltaBase64": delta}}}}, sort_keys=True))
                                    await ws.send_str(json.dumps({{"id": payload["id"], "result": {{"exitCode": 0, "processId": process_id}}}}, sort_keys=True))
                                elif method == "command/exec/write":
                                    process_id = payload["params"]["processId"]
                                    command_writes.setdefault(process_id, []).append(payload["params"]["deltaBase64"])
                                    await ws.send_str(json.dumps({{"method": "command/exec/outputDelta", "params": {{"processId": process_id, "deltaBase64": payload["params"]["deltaBase64"]}}}}, sort_keys=True))
                                    await ws.send_str(json.dumps({{"id": payload["id"], "result": {{"accepted": True}}}}, sort_keys=True))
                            elif payload.get("id") == SERVER_REQUEST_ID:
                                log("server_request_reply", payload)
                        return ws

                    app = web.Application()
                    app.router.add_get("/readyz", readyz)
                    app.router.add_get("/", ws_handler)
                    runner = web.AppRunner(app)
                    await runner.setup()
                    site = web.TCPSite(runner, host, port)
                    await site.start()
                    await asyncio.Event().wait()

                if __name__ == "__main__":
                    asyncio.run(main())
                """
            ),
            encoding="utf-8",
        )
        script_path.chmod(script_path.stat().st_mode | stat.S_IXUSR)

    async def _start_relay_server(self) -> None:
        server_python = (
            Path(__file__).resolve().parents[2]
            / "codex_remote_server"
            / ".venv"
            / "bin"
            / "python"
        )
        self._server_process = await asyncio.create_subprocess_exec(
            str(server_python),
            "-m",
            "codex_remote_server",
            "--host",
            "127.0.0.1",
            "--port",
            str(self._relay_port),
            "--public-base-url",
            f"http://127.0.0.1:{self._relay_port}",
            "--db-path",
            str(self.temp_path / "relay.sqlite3"),
            "--enroll-token",
            "integration-token",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        await self._wait_for_http_ready(f"http://127.0.0.1:{self._relay_port}/healthz")

    async def _start_bridge_cli(self) -> None:
        env = os.environ.copy()
        env["PATH"] = f"{self.temp_path}:{env.get('PATH', '')}"
        self._cli_process = await asyncio.create_subprocess_exec(
            sys.executable,
            "-m",
            "codex_remote_cli",
            "--config",
            str(self._config_path),
            "--relay-url",
            f"http://127.0.0.1:{self._relay_port}",
            "--enroll-token",
            "integration-token",
            "--bridge-label",
            "Integration Bridge",
            "--local-port",
            str(self._app_server_port),
            "serve",
            env=env,
            cwd=str(Path(__file__).resolve().parents[1]),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if self._config_path.exists():
                return
            await asyncio.sleep(0.1)
        raise AssertionError("bridge CLI did not write its config file in time")

    async def _wait_for_pairing_code(self) -> str:
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if self._config_path.exists():
                payload = json.loads(self._config_path.read_text("utf-8"))
                pairing_code = payload.get("pairing_code")
                if pairing_code:
                    return str(pairing_code)
            await asyncio.sleep(0.1)
        raise AssertionError("pairing code was not written to CLI config in time")

    async def _wait_for_http_ready(self, url: str) -> None:
        async with aiohttp.ClientSession() as session:
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                try:
                    async with session.get(url) as response:
                        if response.status == 200:
                            return
                except aiohttp.ClientError:
                    pass
                await asyncio.sleep(0.1)
        raise AssertionError(f"timed out waiting for {url}")

    async def _terminate_process(
        self,
        process: asyncio.subprocess.Process | None,
    ) -> None:
        if process is None or process.returncode is not None:
            return
        process.terminate()
        try:
            await asyncio.wait_for(process.wait(), timeout=5)
        except asyncio.TimeoutError:
            process.kill()
            await process.wait()
