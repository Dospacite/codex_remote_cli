from __future__ import annotations

import argparse
import asyncio
import base64
import json
import os
import shlex
import signal
import shutil
import sys
import tempfile
import time
from io import StringIO
from urllib.parse import urlparse
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import aiohttp
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import qrcode


class RelaySessionClosed(RuntimeError):
    pass


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(value: str) -> bytes:
    padding = "=" * ((4 - len(value) % 4) % 4)
    return base64.urlsafe_b64decode(value + padding)


def canonical_json(data: dict[str, object]) -> bytes:
    return json.dumps(data, separators=(",", ":"), sort_keys=True).encode("utf-8")


def utc_now() -> int:
    return int(time.time())


def generate_token(length: int = 32) -> str:
    return b64url_encode(os.urandom(length))


def resolve_app_server_command(
    command: str,
    *,
    cwd: str | None = None,
) -> list[str]:
    parts = shlex.split(command)
    if not parts:
        raise ValueError("App-server command must not be empty.")

    executable = parts[0]
    candidate = Path(executable).expanduser()
    if candidate.is_absolute():
        if candidate.is_file():
            return [str(candidate), *parts[1:]]
        raise FileNotFoundError(f"Configured app-server binary does not exist: {candidate}")

    if candidate.parent != Path("."):
        resolved = candidate.resolve()
        if resolved.is_file():
            return [str(resolved), *parts[1:]]
        raise FileNotFoundError(f"Configured app-server binary does not exist: {resolved}")

    on_path = shutil.which(executable)
    if on_path:
        return [on_path, *parts[1:]]

    if cwd:
        cwd_candidate = Path(cwd).expanduser() / executable
        if cwd_candidate.is_file():
            return [str(cwd_candidate.resolve()), *parts[1:]]

    searched_cwd = f" or in --app-server-cwd ({cwd})" if cwd else ""
    raise FileNotFoundError(
        f"Unable to find app-server executable '{executable}' on PATH{searched_cwd}. "
        "Set --app-server-bin or CODEX_REMOTE_APP_SERVER_BIN to the correct path."
    )


def session_bundle_payload(
    *,
    device_id: str,
    role: str,
    session_public_key: str,
    session_nonce: str,
    signed_at: int,
) -> bytes:
    return canonical_json(
        {
            "deviceId": device_id,
            "role": role,
            "sessionNonce": session_nonce,
            "sessionPublicKey": session_public_key,
            "signedAt": signed_at,
            "type": "codex-remote-session-bundle-v1",
        }
    )


def auth_payload(
    *,
    challenge: str,
    connection_id: str,
    device_id: str,
    role: str,
    auth_nonce: str,
    auth_timestamp: int,
) -> bytes:
    return canonical_json(
        {
            "authNonce": auth_nonce,
            "authTimestamp": auth_timestamp,
            "challenge": challenge,
            "connectionId": connection_id,
            "deviceId": device_id,
            "role": role,
            "type": "codex-remote-auth-v1",
        }
    )


def derive_session_key(
    *,
    device_id: str,
    private_key: x25519.X25519PrivateKey,
    local_nonce: str,
    peer_public_key: str,
    peer_nonce: str,
) -> bytes:
    shared = private_key.exchange(x25519.X25519PublicKey.from_public_bytes(b64url_decode(peer_public_key)))
    salt = hashes.Hash(hashes.SHA256())
    for value in sorted([local_nonce, peer_nonce]):
        salt.update(value.encode("utf-8"))
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt.finalize(),
        info=device_id.encode("utf-8"),
    )
    return hkdf.derive(shared)


def nonce_for(prefix: bytes, counter: int) -> bytes:
    return prefix + counter.to_bytes(8, "big")


def normalize_pairing_code_relay_url(pairing_code: str, relay_url: str) -> str:
    prefix = "crp1."
    if not pairing_code.startswith(prefix):
        return pairing_code
    try:
        payload = json.loads(b64url_decode(pairing_code[len(prefix) :]))
    except (ValueError, json.JSONDecodeError):
        return pairing_code
    if payload.get("type") != "codex-remote-pairing-v1":
        return pairing_code
    normalized_relay_url = relay_url.rstrip("/")
    if payload.get("relayUrl") == normalized_relay_url:
        return pairing_code
    payload["relayUrl"] = normalized_relay_url
    return prefix + b64url_encode(canonical_json(payload))


def parse_pairing_code_payload(pairing_code: str) -> dict[str, Any] | None:
    prefix = "crp1."
    if not pairing_code.startswith(prefix):
        return None
    try:
        payload = json.loads(b64url_decode(pairing_code[len(prefix) :]))
    except (ValueError, json.JSONDecodeError):
        return None
    if not isinstance(payload, dict):
        return None
    if payload.get("type") != "codex-remote-pairing-v1":
        return None
    return payload


def pairing_code_is_expired(pairing_code: str, *, now: float | None = None) -> bool:
    payload = parse_pairing_code_payload(pairing_code)
    if payload is None:
        return False
    expires_at = payload.get("expiresAt")
    if not isinstance(expires_at, int | float):
        return False
    current_time = time.time() if now is None else now
    return float(expires_at) <= current_time


@dataclass(slots=True)
class BridgeConfig:
    relay_url: str
    bridge_label: str
    device_id: str | None
    bridge_private_key_pem: str
    bridge_signing_public_key: str
    pairing_code: str | None

    @classmethod
    def create(cls, relay_url: str, bridge_label: str) -> "BridgeConfig":
        private_key = ed25519.Ed25519PrivateKey.generate()
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("utf-8")
        public_key = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return cls(
            relay_url=relay_url.rstrip("/"),
            bridge_label=bridge_label,
            device_id=None,
            bridge_private_key_pem=private_pem,
            bridge_signing_public_key=b64url_encode(public_key),
            pairing_code=None,
        )

    @classmethod
    def load(cls, path: Path, relay_url: str, bridge_label: str) -> "BridgeConfig":
        if path.exists():
            raw = json.loads(path.read_text("utf-8"))
            return cls(
                relay_url=str(raw["relay_url"]),
                bridge_label=str(raw["bridge_label"]),
                device_id=raw.get("device_id"),
                bridge_private_key_pem=str(raw["bridge_private_key_pem"]),
                bridge_signing_public_key=str(raw["bridge_signing_public_key"]),
                pairing_code=raw.get("pairing_code"),
            )
        return cls.create(relay_url, bridge_label)

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(asdict(self), indent=2) + "\n", encoding="utf-8")
        path.chmod(0o600)

    @property
    def bridge_private_key(self) -> ed25519.Ed25519PrivateKey:
        return serialization.load_pem_private_key(
            self.bridge_private_key_pem.encode("utf-8"),
            password=None,
        )


@dataclass(slots=True)
class BridgeDownloadOffer:
    token: str
    path: Path
    file_name: str
    size_bytes: int
    expires_at: float


class CodexBridge:
    def __init__(self, args: argparse.Namespace) -> None:
        self._args = args
        _validate_relay_url(args.relay_url)
        self._config_path = Path(args.config).expanduser()
        self._config = BridgeConfig.load(
            self._config_path,
            relay_url=args.relay_url,
            bridge_label=args.bridge_label,
        )
        self._apply_cli_overrides()
        self._stopping = asyncio.Event()
        self._process: asyncio.subprocess.Process | None = None
        self._local_token_file: tempfile.NamedTemporaryFile | None = None
        self._download_offers: dict[str, BridgeDownloadOffer] = {}
        self._download_tasks: set[asyncio.Task[None]] = set()
        self._download_cancellations: dict[str, asyncio.Event] = {}

    def _apply_cli_overrides(self) -> None:
        needs_save = False
        if self._config.relay_url != self._args.relay_url:
            self._config.relay_url = self._args.relay_url.rstrip("/")
            self._config.device_id = None
            self._config.pairing_code = None
            needs_save = True
        if self._config.bridge_label != self._args.bridge_label:
            self._config.bridge_label = self._args.bridge_label
            self._config.pairing_code = None
            needs_save = True
        if self._config.pairing_code is not None:
            normalized_pairing_code = normalize_pairing_code_relay_url(
                self._config.pairing_code,
                self._config.relay_url,
            )
            if normalized_pairing_code != self._config.pairing_code:
                self._config.pairing_code = normalized_pairing_code
                needs_save = True
            if self._config.pairing_code is not None and pairing_code_is_expired(self._config.pairing_code):
                self._config.device_id = None
                self._config.pairing_code = None
                needs_save = True
        if needs_save:
            self._config.save(self._config_path)

    async def run(self) -> None:
        await self._ensure_enrolled()
        if self._args.command == "pairing-code":
            if not self._config.pairing_code:
                print("No pairing code is available. Re-run `serve` with a fresh config.", file=sys.stderr)
                raise SystemExit(1)
            self._print_pairing_materials()
            return
        if self._config.pairing_code:
            self._print_pairing_materials()
        await self._serve_forever()

    def _print_pairing_materials(self) -> None:
        assert self._config.pairing_code is not None
        print("\nPair this bridge with the mobile client using this code or QR:\n")
        print(self._config.pairing_code)
        print("")
        print(render_pairing_qr(self._config.pairing_code))
        print("")

    async def _ensure_enrolled(self) -> None:
        if self._config.device_id:
            return
        headers = {}
        if self._args.enroll_token:
            headers["X-Relay-Enroll-Token"] = self._args.enroll_token
        async with aiohttp.ClientSession() as session:
            async with session.post(
                f"{self._config.relay_url}/api/v1/bridge/enroll",
                headers=headers,
                json={
                    "bridgeLabel": self._config.bridge_label,
                    "bridgeSigningPublicKey": self._config.bridge_signing_public_key,
                },
            ) as response:
                body = await response.text()
                if response.status >= 400:
                    raise RuntimeError(f"Bridge enrollment failed: {response.status} {body}")
                payload = json.loads(body)
        self._config.device_id = payload["deviceId"]
        self._config.pairing_code = normalize_pairing_code_relay_url(
            payload["pairingCode"],
            self._config.relay_url,
        )
        self._config.save(self._config_path)

    async def _serve_forever(self) -> None:
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, self._stopping.set)
        backoff = 1.0
        while not self._stopping.is_set():
            session_task = asyncio.create_task(self._run_single_session())
            stop_task = asyncio.create_task(self._stopping.wait())
            try:
                done, pending = await asyncio.wait(
                    {session_task, stop_task},
                    return_when=asyncio.FIRST_COMPLETED,
                )
                if stop_task in done:
                    session_task.cancel()
                    try:
                        await session_task
                    except asyncio.CancelledError:
                        pass
                    break
                await session_task
                backoff = 1.0
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                print(f"Bridge session failed: {exc}", file=sys.stderr)
                try:
                    await asyncio.wait_for(self._stopping.wait(), timeout=backoff)
                except asyncio.TimeoutError:
                    pass
                backoff = min(backoff * 2.0, 15.0)
            finally:
                for task in (session_task, stop_task):
                    if not task.done():
                        task.cancel()
                for task in (session_task, stop_task):
                    try:
                        await task
                    except asyncio.CancelledError:
                        pass
        await self._shutdown_local_process()

    async def _run_single_session(self) -> None:
        assert self._config.device_id is not None
        process = await self._start_local_app_server()
        async with aiohttp.ClientSession() as session:
            relay_ws = await self._connect_relay(session)
            local_ws = await self._connect_local_app_server(session)
            try:
                await self._relay_messages(relay_ws, local_ws)
            finally:
                await relay_ws.close()
                await local_ws.close()
                if process.returncode is not None:
                    await self._shutdown_local_process()

    async def _start_local_app_server(self) -> asyncio.subprocess.Process:
        if self._process and self._process.returncode is None:
            return self._process
        token = generate_token(24)
        token_file = tempfile.NamedTemporaryFile("w+", delete=False)
        token_file.write(token + "\n")
        token_file.flush()
        self._local_token_file = token_file
        app_server_command = resolve_app_server_command(
            self._args.app_server_bin,
            cwd=self._args.app_server_cwd,
        )
        command = [
            *app_server_command,
            "--listen",
            f"ws://127.0.0.1:{self._args.local_port}",
            "--ws-auth",
            "capability-token",
            "--ws-token-file",
            token_file.name,
        ]
        self._process = await asyncio.create_subprocess_exec(
            *command,
            cwd=self._args.app_server_cwd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        asyncio.create_task(self._stream_output(self._process.stdout, "app-server"))
        asyncio.create_task(self._stream_output(self._process.stderr, "app-server"))
        await self._wait_until_ready()
        return self._process

    async def _wait_until_ready(self) -> None:
        deadline = time.monotonic() + self._args.ready_timeout
        async with aiohttp.ClientSession() as session:
            while time.monotonic() < deadline:
                try:
                    async with session.get(f"http://127.0.0.1:{self._args.local_port}/readyz") as response:
                        if response.status == 200:
                            return
                except aiohttp.ClientError:
                    pass
                await asyncio.sleep(0.5)
        raise RuntimeError("Timed out waiting for the local app-server to become ready.")

    async def _connect_local_app_server(self, session: aiohttp.ClientSession) -> aiohttp.ClientWebSocketResponse:
        assert self._local_token_file is not None
        token = Path(self._local_token_file.name).read_text("utf-8").strip()
        return await session.ws_connect(
            f"ws://127.0.0.1:{self._args.local_port}",
            headers={"Authorization": f"Bearer {token}"},
            heartbeat=20,
        )

    async def _connect_relay(self, session: aiohttp.ClientSession) -> aiohttp.ClientWebSocketResponse:
        ws = await session.ws_connect(f"{self._config.relay_url}/ws", heartbeat=20)
        challenge_message = await ws.receive_json()
        if challenge_message.get("type") != "challenge":
            raise RuntimeError("Relay did not send an authentication challenge.")
        connection_id = str(challenge_message["connectionId"])
        challenge = str(challenge_message["challenge"])
        auth_nonce = generate_token(12)
        auth_timestamp = utc_now()
        session_private = x25519.X25519PrivateKey.generate()
        session_public_key = b64url_encode(
            session_private.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
        )
        session_nonce = generate_token(12)
        signed_at = utc_now()
        bridge_private = self._config.bridge_private_key
        auth_signature = b64url_encode(
            bridge_private.sign(
                auth_payload(
                    challenge=challenge,
                    connection_id=connection_id,
                    device_id=self._config.device_id or "",
                    role="bridge",
                    auth_nonce=auth_nonce,
                    auth_timestamp=auth_timestamp,
                )
            )
        )
        session_signature = b64url_encode(
            bridge_private.sign(
                session_bundle_payload(
                    device_id=self._config.device_id or "",
                    role="bridge",
                    session_public_key=session_public_key,
                    session_nonce=session_nonce,
                    signed_at=signed_at,
                )
            )
        )
        await ws.send_json(
            {
                "authNonce": auth_nonce,
                "authSignature": auth_signature,
                "authTimestamp": auth_timestamp,
                "deviceId": self._config.device_id,
                "role": "bridge",
                "sessionBundle": {
                    "sessionNonce": session_nonce,
                    "sessionPublicKey": session_public_key,
                    "signature": session_signature,
                    "signedAt": signed_at,
                },
                "type": "authenticate",
            }
        )
        session_open = None
        while True:
            message = await ws.receive()
            if message.type == aiohttp.WSMsgType.TEXT:
                payload = json.loads(message.data)
                if payload.get("type") == "authenticated":
                    continue
                if payload.get("type") != "session_open":
                    raise RuntimeError(f"Unexpected relay message before session_open: {payload}")
                session_open = payload
                break
            if message.type in {
                aiohttp.WSMsgType.PING,
                aiohttp.WSMsgType.PONG,
                aiohttp.WSMsgType.CONTINUATION,
            }:
                continue
            raise RuntimeError(f"Relay closed before session_open: {message.type} {message.extra}")
        self._install_session(
            ws=ws,
            session_private=session_private,
            session_nonce=session_nonce,
            session_open=session_open,
        )
        ws._codex_remote_crypto = {
            "session_nonce": session_nonce,
            "session_private": session_private,
        }
        return ws

    def _install_session(
        self,
        *,
        ws: aiohttp.ClientWebSocketResponse,
        session_private: x25519.X25519PrivateKey,
        session_nonce: str,
        session_open: dict[str, Any],
    ) -> None:
        peer_bundle = session_open["peerSessionBundle"]
        peer_public_key = str(peer_bundle["sessionPublicKey"])
        peer_nonce = str(peer_bundle["sessionNonce"])
        key = derive_session_key(
            device_id=self._config.device_id or "",
            private_key=session_private,
            local_nonce=session_nonce,
            peer_public_key=peer_public_key,
            peer_nonce=peer_nonce,
        )
        ws._codex_remote_state = {
            "device_id": self._config.device_id,
            "session_id": str(session_open["sessionId"]),
            "send_counter": 0,
            "receive_counter": 0,
            "cipher": ChaCha20Poly1305(key),
        }

    async def _relay_messages(
        self,
        relay_ws: aiohttp.ClientWebSocketResponse,
        local_ws: aiohttp.ClientWebSocketResponse,
    ) -> None:
        async def pump_local_to_relay() -> None:
            while True:
                message = await local_ws.receive()
                if message.type == aiohttp.WSMsgType.TEXT:
                    relay_state = relay_ws._codex_remote_state
                    counter = relay_state["send_counter"]
                    relay_state["send_counter"] += 1
                    session_id = relay_state["session_id"]
                    device_id = relay_state["device_id"]
                    cipher = relay_state["cipher"]
                    nonce = nonce_for(b"BRDG", counter)
                    aad = canonical_json(
                        {
                            "counter": counter,
                            "deviceId": device_id,
                            "sessionId": session_id,
                            "type": "relay-frame-v1",
                        }
                    )
                    ciphertext = cipher.encrypt(nonce, message.data.encode("utf-8"), aad)
                    await self._send_relay_json(
                        relay_ws,
                        {
                            "counter": counter,
                            "ciphertext": b64url_encode(ciphertext),
                            "sessionId": session_id,
                            "type": "relay_frame",
                        },
                    )
                    continue
                if message.type in {
                    aiohttp.WSMsgType.PING,
                    aiohttp.WSMsgType.PONG,
                    aiohttp.WSMsgType.CONTINUATION,
                }:
                    continue
                if message.type in {
                    aiohttp.WSMsgType.CLOSE,
                    aiohttp.WSMsgType.CLOSING,
                    aiohttp.WSMsgType.CLOSED,
                    aiohttp.WSMsgType.ERROR,
                }:
                    raise RelaySessionClosed(f"Local app-server websocket closed: {message.type} {message.extra}")
                raise RelaySessionClosed(f"Unexpected local websocket message: {message.type}")

        async def pump_relay_to_local() -> None:
            while True:
                message = await relay_ws.receive()
                if message.type == aiohttp.WSMsgType.TEXT:
                    payload = json.loads(message.data)
                elif message.type in {
                    aiohttp.WSMsgType.PING,
                    aiohttp.WSMsgType.PONG,
                    aiohttp.WSMsgType.CONTINUATION,
                }:
                    continue
                elif message.type in {
                    aiohttp.WSMsgType.CLOSE,
                    aiohttp.WSMsgType.CLOSING,
                    aiohttp.WSMsgType.CLOSED,
                    aiohttp.WSMsgType.ERROR,
                }:
                    raise RelaySessionClosed(f"Relay websocket closed: {message.type} {message.extra}")
                else:
                    raise RelaySessionClosed(f"Unexpected relay websocket message: {message.type}")
                relay_state = relay_ws._codex_remote_state
                if payload.get("type") == "relay_frame":
                    if payload.get("sessionId") != relay_state["session_id"]:
                        continue
                    counter = int(payload["counter"])
                    expected = relay_state["receive_counter"]
                    if counter != expected:
                        raise RuntimeError(f"Unexpected relay frame counter: expected {expected}, received {counter}")
                    relay_state["receive_counter"] += 1
                    nonce = nonce_for(b"CLNT", counter)
                    aad = canonical_json(
                        {
                            "counter": counter,
                            "deviceId": relay_state["device_id"],
                            "sessionId": relay_state["session_id"],
                            "type": "relay-frame-v1",
                        }
                    )
                    plaintext = relay_state["cipher"].decrypt(
                        nonce,
                        b64url_decode(str(payload["ciphertext"])),
                        aad,
                    )
                    decoded = plaintext.decode("utf-8")
                    if await self._handle_bridge_local_request(relay_ws, decoded):
                        continue
                    await self._send_local_text(local_ws, decoded)
                elif payload.get("type") == "bridge_download_request":
                    task = asyncio.create_task(
                        self._stream_bridge_download(relay_ws, payload)
                    )
                    self._download_tasks.add(task)
                    task.add_done_callback(self._download_tasks.discard)
                elif payload.get("type") == "bridge_download_cancel":
                    request_id = str(payload.get("requestId", "")).strip()
                    cancellation = self._download_cancellations.get(request_id)
                    if cancellation is not None:
                        cancellation.set()
                elif payload.get("type") == "close_session":
                    raise RelaySessionClosed("The remote client closed the relay session.")
                elif payload.get("type") == "session_open":
                    crypto_state = relay_ws._codex_remote_crypto
                    self._install_session(
                        ws=relay_ws,
                        session_private=crypto_state["session_private"],
                        session_nonce=crypto_state["session_nonce"],
                        session_open=payload,
                    )

        done, pending = await asyncio.wait(
            [
                asyncio.create_task(pump_local_to_relay()),
                asyncio.create_task(pump_relay_to_local()),
                asyncio.create_task(self._stopping.wait()),
            ],
            return_when=asyncio.FIRST_COMPLETED,
        )
        for task in pending:
            task.cancel()
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)
        for task in done:
            if task.cancelled():
                continue
            exception = task.exception()
            if exception is not None:
                raise exception

    async def _handle_bridge_local_request(
        self,
        relay_ws: aiohttp.ClientWebSocketResponse,
        payload_text: str,
    ) -> bool:
        try:
            payload = json.loads(payload_text)
        except json.JSONDecodeError:
            return False
        if not isinstance(payload, dict):
            return False

        request_id = payload.get("id")
        method = payload.get("method")
        params = payload.get("params")
        if not isinstance(request_id, int) or not isinstance(method, str):
            return False
        if not isinstance(params, dict):
            params = {}

        try:
            if method == "fs/readDirectory":
                path = str(params.get("path", "")).strip()
                result = {
                    "entries": await asyncio.to_thread(self._read_directory_entries, path),
                }
            elif method == "fs/readFile":
                path = str(params.get("path", "")).strip()
                data = await asyncio.to_thread(Path(path).read_bytes)
                result = {"dataBase64": base64.b64encode(data).decode("ascii")}
            elif method == "bridge/download/start":
                path = str(params.get("path", "")).strip()
                result = await asyncio.to_thread(self._create_download_offer, path)
            else:
                return False
        except (OSError, ValueError) as exc:
            await self._send_payload_to_relay_peer(
                relay_ws,
                {
                    "id": request_id,
                    "error": {
                        "code": -32603,
                        "message": str(exc),
                    },
                },
            )
            return True

        await self._send_payload_to_relay_peer(
            relay_ws,
            {
                "id": request_id,
                "result": result,
            },
        )
        return True

    def _read_directory_entries(self, path: str) -> list[dict[str, object]]:
        if not path:
            raise ValueError("Missing `path`.")
        entries: list[dict[str, object]] = []
        with os.scandir(path) as iterator:
            for entry in iterator:
                try:
                    is_directory = entry.is_dir(follow_symlinks=False)
                except OSError:
                    is_directory = False
                try:
                    is_file = entry.is_file(follow_symlinks=False)
                except OSError:
                    is_file = False
                entries.append(
                    {
                        "fileName": entry.name,
                        "isDirectory": is_directory,
                        "isFile": is_file,
                    }
                )
        return entries

    def _create_download_offer(self, path: str) -> dict[str, object]:
        if not path:
            raise ValueError("Missing `path`.")
        file_path = Path(path)
        if not file_path.is_file():
            raise ValueError(f"File does not exist: {path}")
        token = generate_token(18)
        stat_result = file_path.stat()
        self._download_offers[token] = BridgeDownloadOffer(
            token=token,
            path=file_path,
            file_name=file_path.name,
            size_bytes=int(stat_result.st_size),
            expires_at=time.time() + 300,
        )
        return {
            "url": f"{self._config.relay_url}/api/v1/bridge-download/{self._config.device_id}/{token}",
            "fileName": file_path.name,
            "sizeBytes": int(stat_result.st_size),
        }

    async def _stream_bridge_download(
        self,
        relay_ws: aiohttp.ClientWebSocketResponse,
        payload: dict[str, Any],
    ) -> None:
        request_id = str(payload.get("requestId", "")).strip()
        token = str(payload.get("token", "")).strip()
        offer = self._download_offers.pop(token, None)
        if not request_id:
            return
        if offer is None or offer.expires_at < time.time():
            await self._send_relay_json(
                relay_ws,
                {
                    "type": "bridge_download_error",
                    "requestId": request_id,
                    "message": "Download token is invalid or has expired.",
                },
            )
            return

        cancellation = asyncio.Event()
        self._download_cancellations[request_id] = cancellation
        try:
            await self._send_relay_json(
                relay_ws,
                {
                    "type": "bridge_download_ready",
                    "requestId": request_id,
                    "fileName": offer.file_name,
                    "sizeBytes": offer.size_bytes,
                    "contentType": "application/octet-stream",
                },
            )
            with offer.path.open("rb") as handle:
                while True:
                    if cancellation.is_set():
                        return
                    chunk = handle.read(256 * 1024)
                    if not chunk:
                        break
                    await self._send_relay_json(
                        relay_ws,
                        {
                            "type": "bridge_download_chunk",
                            "requestId": request_id,
                            "dataBase64": base64.b64encode(chunk).decode("ascii"),
                        },
                    )
            await self._send_relay_json(
                relay_ws,
                {
                    "type": "bridge_download_complete",
                    "requestId": request_id,
                },
            )
        except (OSError, RuntimeError, aiohttp.ClientError) as exc:
            await self._send_relay_json(
                relay_ws,
                {
                    "type": "bridge_download_error",
                    "requestId": request_id,
                    "message": str(exc),
                },
            )
        finally:
            self._download_cancellations.pop(request_id, None)

    async def _send_local_text(
        self,
        local_ws: aiohttp.ClientWebSocketResponse,
        payload: str,
    ) -> None:
        try:
            await local_ws.send_str(payload)
        except (aiohttp.ClientConnectionError, ConnectionResetError, RuntimeError) as exc:
            raise RelaySessionClosed(f"Failed to write to local app-server websocket: {exc}") from exc

    async def _send_payload_to_relay_peer(
        self,
        relay_ws: aiohttp.ClientWebSocketResponse,
        payload: dict[str, Any],
    ) -> None:
        relay_state = relay_ws._codex_remote_state
        counter = relay_state["send_counter"]
        relay_state["send_counter"] += 1
        session_id = relay_state["session_id"]
        device_id = relay_state["device_id"]
        cipher = relay_state["cipher"]
        nonce = nonce_for(b"BRDG", counter)
        aad = canonical_json(
            {
                "counter": counter,
                "deviceId": device_id,
                "sessionId": session_id,
                "type": "relay-frame-v1",
            }
        )
        plaintext = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
        ciphertext = cipher.encrypt(nonce, plaintext, aad)
        await self._send_relay_json(
            relay_ws,
            {
                "counter": counter,
                "ciphertext": b64url_encode(ciphertext),
                "sessionId": session_id,
                "type": "relay_frame",
            },
        )

    async def _send_relay_json(
        self,
        relay_ws: aiohttp.ClientWebSocketResponse,
        payload: dict[str, Any],
    ) -> None:
        try:
            await relay_ws.send_json(payload)
        except (aiohttp.ClientConnectionError, ConnectionResetError, RuntimeError) as exc:
            raise RelaySessionClosed(f"Failed to write to relay websocket: {exc}") from exc

    async def _stream_output(
        self,
        stream: asyncio.StreamReader | None,
        prefix: str,
    ) -> None:
        if stream is None:
            return
        while not stream.at_eof():
            line = await stream.readline()
            if not line:
                break
            print(f"[{prefix}] {line.decode('utf-8', errors='replace').rstrip()}", file=sys.stderr)

    async def _shutdown_local_process(self) -> None:
        if self._process and self._process.returncode is None:
            self._process.terminate()
            try:
                await asyncio.wait_for(self._process.wait(), timeout=10)
            except asyncio.TimeoutError:
                self._process.kill()
                await self._process.wait()
        self._process = None
        if self._local_token_file is not None:
            try:
                os.unlink(self._local_token_file.name)
            except FileNotFoundError:
                pass
            self._local_token_file.close()
            self._local_token_file = None


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Codex Remote bridge CLI")
    parser.add_argument("--config", default="~/.config/codex_remote_cli/config.json")
    parser.add_argument("--relay-url", default=os.getenv("CODEX_REMOTE_RELAY_URL", "https://cr.rousoftware.com"))
    parser.add_argument("--bridge-label", default=os.getenv("CODEX_REMOTE_BRIDGE_LABEL", "My workstation"))
    parser.add_argument("--enroll-token", default=os.getenv("CODEX_REMOTE_ENROLL_TOKEN"))
    parser.add_argument("--local-port", type=int, default=int(os.getenv("CODEX_REMOTE_LOCAL_PORT", "47123")))
    parser.add_argument("--ready-timeout", type=int, default=int(os.getenv("CODEX_REMOTE_READY_TIMEOUT", "30")))
    parser.add_argument("--app-server-bin", default=os.getenv("CODEX_REMOTE_APP_SERVER_BIN", "codex app-server"))
    parser.add_argument("--app-server-cwd", default=os.getenv("CODEX_REMOTE_APP_SERVER_CWD"))
    subparsers = parser.add_subparsers(dest="command")
    subparsers.required = False
    subparsers.add_parser("serve")
    subparsers.add_parser("pairing-code")
    return parser


def _validate_relay_url(value: str) -> None:
    parsed = urlparse(value)
    if parsed.scheme == "https" and parsed.hostname:
        return
    if parsed.scheme == "http" and parsed.hostname in {"localhost", "127.0.0.1", "::1"}:
        return
    raise ValueError("Relay URL must use HTTPS unless it targets localhost for development.")


def render_pairing_qr(pairing_code: str) -> str:
    qr = qrcode.QRCode(border=1)
    qr.add_data(pairing_code)
    qr.make(fit=True)
    buffer = StringIO()
    qr.print_ascii(out=buffer, tty=False, invert=True)
    return buffer.getvalue().rstrip()


def main() -> None:
    args = build_parser().parse_args()
    if not args.command:
        args.command = "serve"
    try:
        bridge = CodexBridge(args)
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc
    asyncio.run(bridge.run())


if __name__ == "__main__":
    main()
