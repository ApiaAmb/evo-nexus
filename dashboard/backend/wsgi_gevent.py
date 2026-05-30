"""Gunicorn + GeventWebSocketWorker entrypoint.

Ordem CRÍTICA: monkey-patch DEVE ser a primeira coisa que executa,
antes de qualquer import que toque socket, threading, subprocess ou
drivers DB (em especial psycopg2).

Invocação canônica (D-W4):

    gunicorn \\
      --worker-class geventwebsocket.gunicorn.workers.GeventWebSocketWorker \\
      --workers 1 \\
      --timeout 86400 \\
      --graceful-timeout 30 \\
      --keep-alive 75 \\
      --bind 0.0.0.0:8080 \\
      --access-logfile - \\
      --error-logfile - \\
      --capture-output \\
      wsgi_gevent:app

Rollback: definir EVONEXUS_USE_GUNICORN=false no swarm para cair no
`python app.py` (Werkzeug). Ver D-W5 no ADR.
"""
from gevent import monkey

monkey.patch_all()  # deve vir antes de qualquer outro import

# psycopg2 não é gevent-aware nativamente. Sem este patch o pool stala
# o worker no primeiro hit dos endpoints /api/knowledge/*.
from psycogreen.gevent import patch_psycopg  # noqa: E402

patch_psycopg()

# SÓ AGORA importa a app.
from app import app, init_task_poller  # noqa: E402

init_task_poller(app)
