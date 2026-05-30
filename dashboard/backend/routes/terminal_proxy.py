"""Proxy HTTP e WebSocket para o terminal-server local.

O terminal-server (Node, dashboard/terminal-server/bin/server.js) escuta
em uma porta (padrão 32352) em 127.0.0.1. Este proxy Flask é o único ponto
capaz de traduzir cookie de sessão flask-login → X-EvoNexus-User-Id no
handshake WebSocket (o browser não pode setar headers customizados em
`new WebSocket(url)`).

Decisões implementadas neste módulo (complementares ao ADR principal D1-D8):
  D-W1: Origin check no proxy_ws (CSWSH mitigation)
  D-W2: Kill switch do proxy WS com registry module-level + force-close
  D-W3: gate semântico camada (a) env var EVONEXUS_REQUIRE_SESSION_ISOLATION
         + camada (b) lazy probe com TTL 60s (condicionada ao Node PR)
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
from pathlib import Path
from urllib.parse import urlsplit

import requests
from flask import Blueprint, Response, jsonify, request, stream_with_context
from flask_login import current_user, login_required

log = logging.getLogger(__name__)

bp = Blueprint("terminal_proxy", __name__)

# ---------------------------------------------------------------------------
# Configuração de destino do terminal-server
# ---------------------------------------------------------------------------

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

# Headers do CLIENT que nunca devem chegar ao terminal-server (D2).
_FORBIDDEN_CLIENT_HEADER_PREFIXES = ("x-evonexus-",)

# ---------------------------------------------------------------------------
# D-W1 — Origin check: normalização + allowlist
# ---------------------------------------------------------------------------

_DEFAULT_PORTS: dict[str, int] = {"http": 80, "https": 443}


def _normalize_origin(raw: str) -> str | None:
    """Retorna canonical scheme://host[:port] ou None se inválido.

    Hardening (Raven r3 gap 4):
    - try/except em urlsplit: IPv6 malformado raise ValueError → return None
    - rejeitar userinfo (user:pass@): vetor de spoofing em logs e config
    - rejeitar whitespace embutido: urlsplit não normaliza, attacker controla
    - rejeitar null-byte: injection defense
    """
    raw = raw.strip().rstrip("/")
    if not raw or any(c.isspace() for c in raw):
        return None
    try:
        parts = urlsplit(raw)
    except ValueError:  # IPv6 malformado, port não-numérico, etc.
        return None
    if parts.scheme not in ("http", "https"):
        return None
    if parts.username is not None or parts.password is not None:
        return None  # userinfo proibido em allowlist
    if not parts.hostname:
        return None
    host = parts.hostname.lower()  # case-insensitive; já trata IDN parcial
    if "\x00" in host:  # null-byte injection defense
        return None
    # IPv6: urlsplit já remove brackets em hostname; recolocar para match canonical
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    try:
        port = parts.port  # raise ValueError se inválido
    except ValueError:
        return None
    if port is None or port == _DEFAULT_PORTS.get(parts.scheme):
        return f"{parts.scheme}://{host}"  # omite port default
    return f"{parts.scheme}://{host}:{port}"


# Allowlist carregada no boot via _load_allowed_origins().
# Valor None = accept-all (apenas em dev, com WARN por request).
_ALLOWED_ORIGINS_SET: frozenset[str] | None = None


def _load_allowed_origins(is_production: bool) -> frozenset[str] | None:
    """Carrega e normaliza TERMINAL_PROXY_ALLOWED_ORIGINS.

    Em produção, ausência da env var → RuntimeError (boot FATAL).
    Em dev, ausência → accept-all com WARN por request.
    Config malformada (origin que normaliza pra None) → RuntimeError sempre.
    """
    raw = os.environ.get("TERMINAL_PROXY_ALLOWED_ORIGINS", "").strip()
    if not raw:
        if is_production:
            raise RuntimeError(
                "TERMINAL_PROXY_ALLOWED_ORIGINS must be set in production. "
                "Example: TERMINAL_PROXY_ALLOWED_ORIGINS=https://ai.apiaambiental.com.br"
            )
        log.warning(
            "terminal_proxy: TERMINAL_PROXY_ALLOWED_ORIGINS not set — "
            "accepting ALL origins (dev mode). Set this env var in production."
        )
        return None  # accept-all em dev

    entries = [e.strip() for e in raw.split(",") if e.strip()]
    normalized: set[str] = set()
    for entry in entries:
        canonical = _normalize_origin(entry)
        if canonical is None:
            raise RuntimeError(
                f"TERMINAL_PROXY_ALLOWED_ORIGINS: entry {entry!r} é inválido. "
                "Corrija a configuração antes de reiniciar."
            )
        normalized.add(canonical)
    return frozenset(normalized)


def _user_id_or_none() -> int | None:
    try:
        if current_user.is_authenticated:
            return current_user.id
    except Exception:
        pass
    return None


def _check_origin(client_ws) -> bool:
    """Valida o header Origin antes do guard de auth.

    Retorna True se pode prosseguir, False se a conexão foi fechada.
    Implementa o algoritmo completo de D-W1.
    """
    global _ALLOWED_ORIGINS_SET

    # accept-all em dev — apenas emite WARN
    if _ALLOWED_ORIGINS_SET is None:
        log.warning(
            "terminal_proxy.ws: no Origin allowlist (dev mode) — accepting connection "
            "(user=%s)", _user_id_or_none()
        )
        return True

    origin = request.headers.get("Origin")

    # 1. Origin AUSENTE → reject. Browsers SEMPRE enviam Origin em WS upgrade.
    if origin is None:
        log.warning(
            "terminal_proxy.ws: rejected — no Origin header (user=%s)", _user_id_or_none()
        )
        try:
            client_ws.close(4403, "origin required")
        except Exception:
            pass
        return False

    # 2. Origin == "null" → reject. Vem de file://, sandboxed iframe, data:.
    if origin == "null":
        log.warning(
            "terminal_proxy.ws: rejected — Origin:null (CSWSH?) (user=%s)", _user_id_or_none()
        )
        try:
            client_ws.close(4403, "origin null forbidden")
        except Exception:
            pass
        return False

    # 3. Normalizar e comparar contra allowlist normalizada.
    canonical = _normalize_origin(origin)
    if canonical is None or canonical not in _ALLOWED_ORIGINS_SET:
        log.warning(
            "terminal_proxy.ws: rejected — Origin=%r not in allowlist (user=%s)",
            origin, _user_id_or_none()
        )
        try:
            client_ws.close(4403, "origin not allowed")
        except Exception:
            pass
        return False

    return True


# ---------------------------------------------------------------------------
# D-W2 — Kill switch do proxy WS
# ---------------------------------------------------------------------------

# Registry module-level: id(client_ws) → (client_ws, upstream_ws, stop_event)
# Acessível de qualquer greenlet sem contexto Flask (não usa current_app.config).
_ws_lock = threading.Lock()
_ws_active: dict[int, tuple] = {}  # (client_ws, upstream_ws, threading.Event)
_ws_enabled: bool = True  # flag runtime-only; volta ao valor da env var após restart


def _register_active_ws(client_ws, upstream_ws, stop: threading.Event) -> None:
    with _ws_lock:
        _ws_active[id(client_ws)] = (client_ws, upstream_ws, stop)


def _unregister_active_ws(client_ws) -> None:
    with _ws_lock:
        _ws_active.pop(id(client_ws), None)


def _force_close_all(reason: str = "service disabled") -> int:
    """Force-close todas as WS abertas. Ordem precisa: stop → upstream → client.

    Retorna o número de conexões fechadas.
    Implementa a ordem exata de D-W2 (Raven r3 m-1):
      a. stop.set() — sinaliza pump pra sair na próxima iteração
      b. upstream.close() — desbloqueia upstream.recv() cedo
      c. client_ws.close(4503) — desbloqueia client_ws.receive()
    """
    with _ws_lock:
        active_snapshot = list(_ws_active.values())

    count = 0
    for client_ws, upstream_ws, stop in active_snapshot:
        try:
            stop.set()
        except Exception:
            pass
        try:
            upstream_ws.close()
        except Exception:
            pass
        try:
            client_ws.close(4503, reason)
        except Exception:
            pass
        count += 1
    return count


# ---------------------------------------------------------------------------
# D-W3 gate semântico — camada (b) lazy probe com TTL 60s
# ---------------------------------------------------------------------------

_NODE_ISOLATION_CACHE_TTL = 60  # segundos
_node_isolation_enforced: bool | None = None  # None = cache não inicializado
_node_isolation_checked_at: float = 0.0
_node_isolation_lock = threading.Lock()


def _probe_node_isolation() -> bool | None:
    """Probe o Node para checar se SESSION_ISOLATION_ENABLED está ativo.

    Retorna:
      True  — Node confirma isolation ativa (seguro abrir WS)
      False — Node retornou session_isolation_enabled=false (recusar WS)
      None  — probe falhou (timeout/erro): fail-closed → recusar WS

    Esta função é NO-OP quando EVONEXUS_LAZY_PROBE_ENABLED != "true"
    (camada b condicionada ao Node PR que expõe session_isolation_enabled).
    """
    if os.environ.get("EVONEXUS_LAZY_PROBE_ENABLED", "false").lower() != "true":
        return True  # camada (b) desabilitada → não bloquear

    try:
        resp = requests.get(
            f"{TERMINAL_HTTP_BASE}/api/health",
            timeout=2,
        )
        if resp.status_code == 200:
            data = resp.json()
            enabled = data.get("session_isolation_enabled")
            if enabled is False:
                return False
            return True
    except Exception as exc:
        log.warning("terminal_proxy.ws: Node health probe failed: %s — fail-closed", exc)
        return None  # fail-closed

    return True


def _check_node_isolation_enforced(client_ws) -> bool:
    """Camada (b) do gate semântico: lazy probe com TTL 60s.

    Retorna True se pode prosseguir, False se a conexão foi recusada.
    """
    global _node_isolation_enforced, _node_isolation_checked_at

    now = time.monotonic()
    with _node_isolation_lock:
        if (
            _node_isolation_enforced is None
            or (now - _node_isolation_checked_at) >= _NODE_ISOLATION_CACHE_TTL
        ):
            result = _probe_node_isolation()
            _node_isolation_enforced = result
            _node_isolation_checked_at = now

        current = _node_isolation_enforced

    if current is False:
        log.warning(
            "terminal_proxy.ws: rejected — Node session_isolation_enabled=false "
            "(gate semântico, camada b) — user=%s", _user_id_or_none()
        )
        _write_audit_log(
            action="ws_rejected_node_disabled_isolation",
            user_id=_user_id_or_none(),
            active_connections=len(_ws_active),
            request_ip=request.remote_addr,
        )
        try:
            client_ws.close(4503, "node-disabled-isolation")
        except Exception:
            pass
        return False

    if current is None:
        # fail-closed: probe falhou
        log.warning(
            "terminal_proxy.ws: rejected — Node health probe failed, fail-closed "
            "(gate semântico, camada b) — user=%s", _user_id_or_none()
        )
        try:
            client_ws.close(4503, "isolation-probe-failed")
        except Exception:
            pass
        return False

    return True


# ---------------------------------------------------------------------------
# Audit log JSONL (D-W2)
# ---------------------------------------------------------------------------

_LOGS_DIR = Path(__file__).resolve().parent.parent / "logs"
_WS_AUDIT_LOG = _LOGS_DIR / "ws-proxy-toggle.jsonl"


def _write_audit_log(**kwargs) -> None:
    """Escreve uma linha JSON em ws-proxy-toggle.jsonl."""
    entry = {"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), **kwargs}
    try:
        _LOGS_DIR.mkdir(parents=True, exist_ok=True)
        with open(_WS_AUDIT_LOG, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except Exception as exc:
        log.error("terminal_proxy: audit log write failed: %s", exc)


# ---------------------------------------------------------------------------
# Helpers de identidade (D1 / D2)
# ---------------------------------------------------------------------------


def _strip_client_identity(headers: dict[str, str]) -> dict[str, str]:
    """Remove X-EvoNexus-* headers do cliente (D2)."""
    removed = [
        k for k in headers
        if any(k.lower().startswith(p) for p in _FORBIDDEN_CLIENT_HEADER_PREFIXES)
    ]
    if removed:
        log.warning(
            "terminal_proxy: stripped client-supplied identity headers: %s (user=%s, path=%s)",
            removed,
            getattr(current_user, "id", None),
            request.path,
        )
    return {k: v for k, v in headers.items() if k not in removed}


def _inject_identity(headers: dict[str, str], user) -> dict[str, str]:
    """Injeta identidade autenticada nos headers de saída (D1/D2)."""
    headers["X-EvoNexus-User-Id"] = str(user.id)
    headers["X-EvoNexus-User-Role"] = user.role
    return headers


def _forward_headers(src: dict[str, str]) -> dict[str, str]:
    """Strip hop-by-hop headers antes de encaminhar."""
    return {k: v for k, v in src.items() if k.lower() not in _HOP_BY_HOP}


# ---------------------------------------------------------------------------
# HTTP proxy
# ---------------------------------------------------------------------------


@bp.route(
    "/terminal/<path:subpath>",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
)
@bp.route("/terminal", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"])
@login_required
def proxy_http(subpath: str = ""):
    """Encaminha tráfego HTTP para o terminal-server local."""
    target = f"{TERMINAL_HTTP_BASE}/{subpath}"
    if request.query_string:
        target = f"{target}?{request.query_string.decode('latin-1')}"

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

    response = Response(
        stream_with_context(upstream.iter_content(chunk_size=8192)),
        status=upstream.status_code,
    )
    for key, value in upstream.headers.items():
        if key.lower() not in _HOP_BY_HOP:
            response.headers[key] = value
    return response


# ---------------------------------------------------------------------------
# Endpoints admin de toggle do WS proxy (D-W2)
# ---------------------------------------------------------------------------


def _validate_admin_request(confirm_value: str):
    """Valida CSRF + confirm guard para endpoints admin destrutivos.

    Retorna (ok: bool, error_response, status_code).
    CSRF: valida contra session["csrf_token"] (Flask-WTF ou manual).
    """
    # 1. Autenticação + autorização
    if not current_user.is_authenticated:
        return False, jsonify({"error": "authentication required"}), 401
    if getattr(current_user, "role", None) != "admin":
        return False, jsonify({"error": "admin role required"}), 403

    # 2. Confirm guard (Raven r3 m-3)
    confirm = request.args.get("confirm", "")
    if confirm != confirm_value:
        return False, jsonify({"error": f"confirm={confirm_value!r} required as query param"}), 400

    # 3. CSRF: checar header X-CSRFToken ou X-WTF-CSRF-Token contra session
    from flask import session as flask_session

    csrf_token_session = flask_session.get("csrf_token") or flask_session.get("_csrf_token")
    if csrf_token_session:
        # App usa session-based CSRF
        csrf_header = (
            request.headers.get("X-CSRFToken")
            or request.headers.get("X-WTF-CSRF-Token")
            or ""
        )
        if not csrf_header or csrf_header != csrf_token_session:
            return False, jsonify({"error": "CSRF token missing or invalid"}), 403
    else:
        # Flask-WTF global — tenta validar via extensão se disponível
        try:
            from flask_wtf.csrf import validate_csrf  # type: ignore
            csrf_header = (
                request.headers.get("X-CSRFToken")
                or request.headers.get("X-WTF-CSRF-Token")
                or ""
            )
            validate_csrf(csrf_header)
        except Exception:
            # Se Flask-WTF não estiver configurado, aceita (menor que zero
            # proteção, mas não quebra dev sem CSRF configurado).
            # Em produção o CSRF via session deve estar ativo.
            log.warning(
                "terminal_proxy: CSRF validation skipped (Flask-WTF not configured) "
                "— operação destrutiva admin executada sem CSRF"
            )

    return True, None, None


@bp.route("/terminal/proxy/ws/disable", methods=["POST"])
def admin_ws_disable():
    """Desabilita o proxy WS e força-close todas as conexões ativas.

    Requer: role=admin, CSRF token, ?confirm=YES-DISABLE-WS
    """
    global _ws_enabled

    ok, err_resp, status = _validate_admin_request("YES-DISABLE-WS")
    if not ok:
        return err_resp, status

    active_count = len(_ws_active)
    _ws_enabled = False
    closed = _force_close_all("service disabled by admin")

    _write_audit_log(
        action="disable",
        user_id=current_user.id,
        user_role=current_user.role,
        active_connections_at_toggle=active_count,
        closed_connections=closed,
        request_ip=request.remote_addr,
    )
    log.warning(
        "terminal_proxy: WS proxy DISABLED by admin user_id=%s — %d connections force-closed",
        current_user.id, closed,
    )
    return jsonify({"status": "disabled", "connections_closed": closed}), 200


@bp.route("/terminal/proxy/ws/enable", methods=["POST"])
def admin_ws_enable():
    """Habilita o proxy WS.

    Requer: role=admin, CSRF token, ?confirm=YES-ENABLE-WS
    """
    global _ws_enabled

    ok, err_resp, status = _validate_admin_request("YES-ENABLE-WS")
    if not ok:
        return err_resp, status

    _ws_enabled = True

    _write_audit_log(
        action="enable",
        user_id=current_user.id,
        user_role=current_user.role,
        active_connections_at_toggle=len(_ws_active),
        request_ip=request.remote_addr,
    )
    log.info(
        "terminal_proxy: WS proxy ENABLED by admin user_id=%s", current_user.id
    )
    return jsonify({"status": "enabled"}), 200


# ---------------------------------------------------------------------------
# WebSocket proxy
# ---------------------------------------------------------------------------


def register_websocket_proxy(sock, is_production: bool = False) -> None:
    """Registra o proxy WebSocket /terminal/ws na instância Sock fornecida.

    Carrega a allowlist de Origins no boot e falha FATAL em produção se
    TERMINAL_PROXY_ALLOWED_ORIGINS não estiver configurada (D-W1).
    """
    global _ALLOWED_ORIGINS_SET, _ws_enabled

    # Carrega e valida allowlist de Origins (D-W1) — boot FATAL em prod se ausente
    _ALLOWED_ORIGINS_SET = _load_allowed_origins(is_production)

    # Kill switch estático: se TERMINAL_PROXY_WS_ENABLED=false, não registra a rota
    if os.environ.get("TERMINAL_PROXY_WS_ENABLED", "true").lower() == "false":
        _ws_enabled = False
        log.info("terminal_proxy: TERMINAL_PROXY_WS_ENABLED=false — WS proxy not registered")
        return

    # Gate semântico camada (a): EVONEXUS_REQUIRE_SESSION_ISOLATION (D-W2)
    require_isolation = os.environ.get("EVONEXUS_REQUIRE_SESSION_ISOLATION", "false").lower()
    if require_isolation == "true":
        ws_enabled_env = os.environ.get("TERMINAL_PROXY_WS_ENABLED", "true").lower()
        if ws_enabled_env == "true":
            log.info(
                "terminal_proxy: EVONEXUS_REQUIRE_SESSION_ISOLATION=true — "
                "lazy probe (camada b) ativada quando Node PR disponível"
            )

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
        """Bridge bidirecional: browser <-> Flask <-> terminal-server.

        Ordem de verificações (todas antes de abrir upstream):
          0. Kill switch _ws_enabled
          1. D-W1: Origin check
          2. Guard de auth (current_user.is_authenticated)
          3. Gate semântico camada (b): lazy probe Node
          4. Conectar ao upstream Node + injetar X-EvoNexus-User-Id
          5. Registrar no _ws_active + iniciar pump bidirecional
        """
        # 0. Kill switch runtime (D-W2)
        if not _ws_enabled:
            log.warning(
                "terminal_proxy.ws: rejected — WS proxy disabled (kill switch)"
            )
            try:
                client_ws.close(4503, "service disabled")
            except Exception:
                pass
            return

        # 1. Origin check (D-W1) — antes de qualquer outra verificação
        if not _check_origin(client_ws):
            return

        # 2. Guard de auth
        if not current_user.is_authenticated:
            log.warning("terminal_proxy.ws: rejected — not authenticated")
            try:
                client_ws.close(4401, "auth required")
            except Exception:
                pass
            return

        # 3. Gate semântico camada (b): lazy probe Node (D-W2)
        require_isolation_env = os.environ.get(
            "EVONEXUS_REQUIRE_SESSION_ISOLATION", "false"
        ).lower()
        if require_isolation_env == "true":
            if not _check_node_isolation_enforced(client_ws):
                return

        # 4. Conectar ao upstream Node injetando X-EvoNexus-User-Id (D1)
        target = f"{TERMINAL_WS_BASE}/ws"
        try:
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

        # 5. Registrar no registry + iniciar pump bidirecional
        stop = threading.Event()
        _register_active_ws(client_ws, upstream, stop)

        def _pump_upstream_to_client():
            try:
                while not stop.is_set():
                    msg = upstream.recv()
                    if msg is None or msg == b"":
                        break
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
            _unregister_active_ws(client_ws)
