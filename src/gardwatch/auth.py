"""OAuth 2.1 authentication for the gardwatch CLI."""
import hashlib
import base64
import os
import secrets
import json
import time
import webbrowser
import socket
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse, urlencode
from pathlib import Path
from typing import Optional

import httpx

AUTH_SERVER = os.environ.get("GARDERA_AUTH_SERVER", "https://mcp.gardera.io")
CREDENTIALS_PATH = Path.home() / ".config" / "gardera" / "credentials.json"
CLIENT_NAME = "GardWatch CLI"
CALLBACK_PORT_RANGE = range(18440, 18450)
LOGIN_TIMEOUT_SECONDS = 300


def _generate_pkce() -> tuple[str, str]:
    """Generate PKCE code_verifier and code_challenge (S256)."""
    code_verifier = secrets.token_urlsafe(32)
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    code_challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return code_verifier, code_challenge


def _load_credentials() -> Optional[dict]:
    """Load stored credentials from disk."""
    if not CREDENTIALS_PATH.exists():
        return None
    try:
        return json.loads(CREDENTIALS_PATH.read_text())
    except (json.JSONDecodeError, OSError):
        return None


def _save_credentials(creds: dict) -> None:
    """Save credentials to disk with restricted permissions (owner-only)."""
    CREDENTIALS_PATH.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(CREDENTIALS_PATH, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, json.dumps(creds, indent=2).encode())
    finally:
        os.close(fd)


def _clear_credentials() -> None:
    """Delete credentials file."""
    if CREDENTIALS_PATH.exists():
        CREDENTIALS_PATH.unlink()


def _find_available_port() -> int:
    """Find an available port for the OAuth callback server."""
    for port in CALLBACK_PORT_RANGE:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(("127.0.0.1", port))
                return port
        except OSError:
            continue
    raise RuntimeError("No available port for OAuth callback server")


def _register_client(redirect_uri: str) -> str:
    """Register a new OAuth public client. Returns client_id."""
    response = httpx.post(
        f"{AUTH_SERVER}/register",
        json={
            "redirect_uris": [redirect_uri],
            "token_endpoint_auth_method": "none",
            "client_name": CLIENT_NAME,
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
        },
        timeout=30,
    )
    response.raise_for_status()
    return response.json()["client_id"]


class _CallbackHandler(BaseHTTPRequestHandler):
    """HTTP handler that captures the OAuth authorization code callback."""

    auth_code: Optional[str] = None
    auth_state: Optional[str] = None
    error: Optional[str] = None
    received = threading.Event()

    def do_GET(self):
        query = parse_qs(urlparse(self.path).query)

        if "code" in query:
            _CallbackHandler.auth_code = query["code"][0]
            _CallbackHandler.auth_state = query.get("state", [None])[0]
        elif "error" in query:
            _CallbackHandler.error = query.get("error_description", query["error"])[0]
        else:
            _CallbackHandler.error = "No authorization code received"

        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()

        if _CallbackHandler.error:
            page = b"""<!DOCTYPE html>
<html><head><title>GardWatch</title></head>
<body style="font-family:system-ui;text-align:center;padding:40px">
<h2>Authentication failed</h2>
<p>Return to the terminal for details.</p>
</body></html>"""
        else:
            page = b"""<!DOCTYPE html>
<html><head><title>GardWatch</title></head>
<body style="font-family:system-ui;text-align:center;padding:40px">
<h2>Authentication successful</h2>
<p>You can close this window and return to the terminal.</p>
</body></html>"""

        self.wfile.write(page)
        _CallbackHandler.received.set()

    def log_message(self, format, *args):
        pass


def _exchange_code(
    code: str, code_verifier: str, client_id: str, redirect_uri: str
) -> dict:
    """Exchange authorization code for tokens."""
    response = httpx.post(
        f"{AUTH_SERVER}/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "code_verifier": code_verifier,
            "client_id": client_id,
            "redirect_uri": redirect_uri,
        },
        timeout=30,
    )
    response.raise_for_status()
    return response.json()


def _refresh_tokens(refresh_token: str, client_id: str) -> dict:
    """Refresh access token using refresh token."""
    response = httpx.post(
        f"{AUTH_SERVER}/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": client_id,
        },
        timeout=30,
    )
    response.raise_for_status()
    return response.json()


def _revoke_token(token: str, client_id: str) -> None:
    """Revoke a token (best-effort, errors are ignored)."""
    try:
        httpx.post(
            f"{AUTH_SERVER}/revoke",
            data={"token": token, "client_id": client_id},
            timeout=10,
        )
    except httpx.HTTPError:
        pass


def login() -> None:
    """Run the full OAuth 2.1 login flow. Raises on failure."""
    # Reset handler state
    _CallbackHandler.auth_code = None
    _CallbackHandler.auth_state = None
    _CallbackHandler.error = None
    _CallbackHandler.received.clear()

    # Find available port and build redirect URI
    port = _find_available_port()
    redirect_uri = f"http://127.0.0.1:{port}/callback"

    # Reuse cached client_id if redirect_uri matches, otherwise register new
    creds = _load_credentials()
    client_id = None
    if creds and creds.get("client_id") and creds.get("redirect_uri") == redirect_uri:
        client_id = creds["client_id"]

    if not client_id:
        client_id = _register_client(redirect_uri)

    # Generate PKCE pair and state
    code_verifier, code_challenge = _generate_pkce()
    state = secrets.token_urlsafe(16)

    # Start one-shot callback server
    server = HTTPServer(("127.0.0.1", port), _CallbackHandler)
    server_thread = threading.Thread(target=server.handle_request, daemon=True)
    server_thread.start()

    # Open browser to authorize endpoint
    params = urlencode({
        "client_id": client_id,
        "response_type": "code",
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "redirect_uri": redirect_uri,
        "state": state,
    })
    authorize_url = f"{AUTH_SERVER}/authorize?{params}"
    webbrowser.open(authorize_url)

    # Wait for the browser redirect
    if not _CallbackHandler.received.wait(timeout=LOGIN_TIMEOUT_SECONDS):
        server.server_close()
        raise RuntimeError("Login timed out waiting for browser callback")

    server.server_close()

    if _CallbackHandler.error:
        raise RuntimeError(f"Authentication failed: {_CallbackHandler.error}")

    if not _CallbackHandler.auth_code:
        raise RuntimeError("No authorization code received")

    if _CallbackHandler.auth_state != state:
        raise RuntimeError("State mismatch — possible CSRF attack")

    # Exchange code for tokens
    token_data = _exchange_code(
        _CallbackHandler.auth_code, code_verifier, client_id, redirect_uri
    )

    # Persist credentials
    _save_credentials({
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "access_token": token_data["access_token"],
        "refresh_token": token_data["refresh_token"],
        "expires_at": int(time.time()) + token_data.get("expires_in", 3600),
    })


def logout() -> None:
    """Revoke tokens and clear stored credentials."""
    creds = _load_credentials()
    if not creds:
        raise RuntimeError("Not logged in")

    client_id = creds.get("client_id", "")
    if creds.get("access_token"):
        _revoke_token(creds["access_token"], client_id)
    if creds.get("refresh_token"):
        _revoke_token(creds["refresh_token"], client_id)

    _clear_credentials()


def get_valid_token() -> Optional[str]:
    """Return a valid access token, auto-refreshing if expired. None if not logged in."""
    creds = _load_credentials()
    if not creds or not creds.get("access_token"):
        return None

    # Still valid (with 60s buffer)
    if time.time() < creds.get("expires_at", 0) - 60:
        return creds["access_token"]

    # Try refresh
    refresh_token = creds.get("refresh_token")
    client_id = creds.get("client_id")
    if not refresh_token or not client_id:
        return None

    try:
        token_data = _refresh_tokens(refresh_token, client_id)
    except httpx.HTTPStatusError:
        _clear_credentials()
        return None

    creds["access_token"] = token_data["access_token"]
    creds["refresh_token"] = token_data["refresh_token"]
    creds["expires_at"] = int(time.time()) + token_data.get("expires_in", 3600)
    _save_credentials(creds)
    return creds["access_token"]


def is_logged_in() -> bool:
    """Check whether stored credentials exist."""
    creds = _load_credentials()
    return creds is not None and "access_token" in creds
