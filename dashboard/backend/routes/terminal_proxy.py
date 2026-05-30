"""Proxy HTTP and WebSocket traffic to the local terminal-server.

The terminal-server (Node, dashboard/terminal-server/bin/server.js) binds to
a random port (commonly 32352) on 0.0.0.0. Browsers connecting to the
dashboard from a different host than `localhost` historically had to hit
that port directly, which fails in three common scenarios:

1. Browsing via SSH tunnel (`ssh -L 8080:localhost:8080`) — only port 8080
   is forwarded, the random terminal-server port is not.
2. Browsing via a public tunnel (Tailscale Funnel, Cloudflare Tunnel, an
   nginx reverse proxy on a VPS) — only the dashboard port is exposed.
3. Browsing on a LAN where macOS Application Firewall hasn't whitelisted
   the random port for the Node binary.

Mounting a proxy on the same Flask app the user is already authenticated
to fixes all three: the terminal-server is reachable wherever the
dashboard is reachable, on the same origin, with no extra ports to
expose.

This module is intentionally minimal — it forwards bytes both ways for
HTTP and WebSocket; it does not inspect or rewrite payloads.
"""

from __future__ import annotations

import logging
import os
import threading

import requests
from flask import Blueprint, Response, request, stream_with_context
from flask_login import current_user, login_required

log = logging.getLogger(__name__)

bp = Blueprint("terminal_proxy", __name__)

# Where the local terminal-server lives. The Node script defaults to 32352
# but can be overridden — keep this in sync via env var.
TERMINAL_HOST = os.environ.get("TERMINAL_SERVER_HOST", "127.0.0.1")
TERMINAL_PORT = int(os.environ.get("TERMINAL_SERVER_PORT", "32352"))
TERMINAL_HTTP_BASE = f"http://{TERMINAL_HOST}:{TERMINAL_PORT}"
TERMINAL_WS_BASE = f"ws://{TERMINAL_HOST}:{TERMINAL_PORT}"

# Hop-by-hop headers that must not be forwarded (RFC 7230 §6.1).
_HOP_BY_HOP = frozenset(
    {
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailers",
        "transfer-encoding",
        "upgrade",
        "host",
        "content-length",  # let requests/Flask compute it
    }
)

# Headers from the CLIENT that must never reach the terminal-server (D2).
# Any header with this prefix is stripped from client request and re-injected
# with the value resolved from the authenticated Flask session.
_FORBIDDEN_CLIENT_HEADER_PREFIXES = ("x-evonexus-",)


def _strip_client_identity(headers: dict[str, str]) -> dict[str, str]:
    """Remove any X-EvoNexus-* headers supplied by the client (D2).

    These are controlled by the proxy only. Stripping prevents privilege
    escalation where a client forges X-EvoNexus-User-Id: 1.
    Logs a warning with the removed header names for audit trail.
    """
    removed = [k for k in headers if any(k.lower().startswith(p) for p in _FORBIDDEN_CLIENT_HEADER_PREFIXES)]
    if removed:
        log.warning(
            "terminal_proxy: stripped client-supplied identity headers: %s (user=%s, path=%s)",
            removed,
            getattr(current_user, "id", None),
            request.path,
        )
    return {k: v for k, v in headers.items() if k not in removed}


def _inject_identity(headers: dict[str, str], user) -> dict[str, str]:
    """Inject authenticated user identity into outgoing headers (D1/D2).

    This is the ONLY source of X-EvoNexus-User-Id seen by the terminal-server.
    Must always be called AFTER _strip_client_identity on the same headers dict.
    """
    headers["X-EvoNexus-User-Id"] = str(user.id)
    headers["X-EvoNexus-User-Role"] = user.role
    return headers


def _forward_headers(src: dict[str, str]) -> dict[str, str]:
    """Strip hop-by-hop headers before forwarding either direction."""
    return {k: v for k, v in src.items() if k.lower() not in _HOP_BY_HOP}


# ---------------------------------------------------------------------------
# HTTP proxy — covers /api/health, /api/sessions/*, /api/notifications/*, etc.
# ---------------------------------------------------------------------------

@bp.route(
    "/terminal/<path:subpath>",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
)
@bp.route("/terminal", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"])
@login_required
def proxy_http(subpath: str = ""):
    """Forward HTTP traffic to the local terminal-server."""
    target = f"{TERMINAL_HTTP_BASE}/{subpath}"
    if request.query_string:
        target = f"{target}?{request.query_string.decode('latin-1')}"

    # Build forwarded headers: strip hop-by-hop AND strip+inject identity (D2).
    fwd_headers = _forward_headers(dict(request.headers))
    fwd_headers = _strip_client_identity(fwd_headers)
    fwd_headers = _inject_identity(fwd_headers, current_user)

    try:
        upstream = requests.request(
            method=request.method,
            url=target,
            headers=fwd_headers,
            data=request.get_data(),
            allow_redirects=False,
            stream=True,
            timeout=30,
        )
    except requests.exceptions.ConnectionError:
        return (
            "Terminal-server is not running. Start it via `make terminal-server` "
            "or `node dashboard/terminal-server/bin/server.js --dev`.",
            503,
        )
    except requests.exceptions.Timeout:
        return "Terminal-server timed out.", 504

    # Pass through status, body, headers (minus hop-by-hop).
    response = Response(
        stream_with_context(upstream.iter_content(chunk_size=8192)),
        status=upstream.status_code,
    )
    for key, value in upstream.headers.items():
        if key.lower() not in _HOP_BY_HOP:
            response.headers[key] = value
    return response


# ---------------------------------------------------------------------------
# WebSocket proxy — terminal stream + notifications
# ---------------------------------------------------------------------------
# Registered at app-creation time via `register_websocket_proxy(sock)` so
# we can use the shared `flask_sock.Sock` instance the rest of the app uses.

def register_websocket_proxy(sock) -> None:
    """Register the /terminal/ws WebSocket proxy on the given Sock instance.

    Why not a plain `@bp.route` decorator: flask-sock requires its own
    `@sock.route(...)` decorator, and the Sock instance is created in
    ``app.py``. Calling this from there keeps the dependency one-way.
    """
    try:
        from websocket import create_connection  # type: ignore
    except ImportError:
        log.warning(
            "terminal_proxy.register_websocket_proxy: websocket-client not "
            "installed; WebSocket proxy disabled. Add `websocket-client` "
            "to dependencies."
        )
        return

    @sock.route("/terminal/ws")
    def proxy_ws(client_ws):
        """Bidirectional bridge: browser <-> Flask <-> terminal-server.

        Auth: the global ``auth_middleware`` only gates ``/api/*`` and
        ``/ws/*`` paths, so a request to ``/terminal/ws`` is *not* checked
        upstream. Without the explicit ``current_user.is_authenticated``
        guard below, anyone able to reach the dashboard (LAN, Tailscale
        Funnel, Cloudflare Tunnel, public VPS) could open a PTY on the
        host. flask-login's session cookie is read from the WS upgrade
        request, so this works the same as ``@login_required`` on HTTP
        routes.
        """
        if not current_user.is_authenticated:
            try:
                client_ws.close(reason="auth required")
            except Exception:
                pass
            return

        target = f"{TERMINAL_WS_BASE}/ws"
        try:
            # Inject authenticated identity into the server→server upgrade (D1).
            # The browser cannot set arbitrary headers on WebSocket upgrade;
            # only the Flask proxy can. This is the SOLE source of truth for
            # the terminal-server's knowledge of which user owns this WS connection.
            upstream = create_connection(
                target,
                timeout=10,
                header=[
                    f"X-EvoNexus-User-Id: {current_user.id}",
                    f"X-EvoNexus-User-Role: {current_user.role}",
                ],
            )
        except Exception as exc:
            log.warning("terminal_proxy: upstream WS connect failed: %s", exc)
            try:
                client_ws.close(reason=f"upstream unreachable: {exc}")
            except Exception:
                pass
            return

        stop = threading.Event()

        def _pump_upstream_to_client():
            try:
                while not stop.is_set():
                    msg = upstream.recv()
                    if msg is None or msg == b"":
                        break
                    if isinstance(msg, bytes):
                        client_ws.send(msg)
                    else:
                        client_ws.send(msg)
            except Exception:
                pass
            finally:
                stop.set()
                try:
                    client_ws.close()
                except Exception:
                    pass

        t = threading.Thread(target=_pump_upstream_to_client, daemon=True)
        t.start()

        try:
            while not stop.is_set():
                msg = client_ws.receive(timeout=30)
                if msg is None:
                    break
                upstream.send(msg)
        except Exception:
            pass
        finally:
            stop.set()
            try:
                upstream.close()
            except Exception:
                pass
