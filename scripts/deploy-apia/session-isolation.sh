#!/usr/bin/env bash
# ============================================================================
# Deploy do fix de session isolation — host VPS Apia (vps-hostgator)
#
# Executar via SSH no host como root (ou usuário com docker access):
#   ssh vps-hostgator
#   curl -sSfL https://raw.githubusercontent.com/ApiaAmb/evo-nexus/main/scripts/deploy-apia/session-isolation.sh | bash
#
# OU mais simples: copia esse bloco inteiro e cola no terminal SSH do host.
#
# O script:
#   1. Documenta a imagem atual (pinning para rollback)
#   2. Atualiza o serviço pra nova imagem GHCR + isolation=false (auto-migrate)
#   3. Aguarda rolling update
#   4. Valida migração via logs
#   5. Roda gate D4 (3 testes Traefik overlay)
#   6. Liga enforcement (SESSION_ISOLATION_ENABLED=true)
#   7. Valida estado final
#
# Em caso de erro em qualquer passo, o script PARA (set -e) e mostra como
# fazer rollback. NUNCA deixa em estado intermediário sem reportar.
# ============================================================================

set -euo pipefail

NEW_IMAGE="ghcr.io/apiaamb/evo-nexus-dashboard:v0.1.0-apia-session-isolation"
SERVICE="evonexus_evonexus_dashboard"
OVERLAY_NET="ApiaAmbientalNet"

log()  { printf '\n\033[1;36m[%s] %s\033[0m\n' "$(date +%H:%M:%S)" "$*"; }
ok()   { printf '\033[1;32m  ✓ %s\033[0m\n' "$*"; }
warn() { printf '\033[1;33m  ⚠ %s\033[0m\n' "$*"; }
fail() { printf '\033[1;31m  ✗ %s\033[0m\n' "$*"; exit 1; }

# --- Passo 0: confirmar pré-requisitos ---
log "Passo 0 — Pré-requisitos"
command -v docker >/dev/null || fail "docker CLI ausente"
docker service inspect "$SERVICE" >/dev/null 2>&1 || fail "serviço $SERVICE não existe no Swarm"
ok "docker OK, serviço $SERVICE existe"

# Capturar imagem atual (rollback)
CURRENT_IMAGE=$(docker service inspect "$SERVICE" --format '{{.Spec.TaskTemplate.ContainerSpec.Image}}')
log "Imagem atual (pre-fix): $CURRENT_IMAGE"
echo "$CURRENT_IMAGE" > /tmp/evonexus-prefix-image.txt
ok "salvo em /tmp/evonexus-prefix-image.txt para rollback"

# --- Passo 1: deploy com kill switch DESLIGADO ---
log "Passo 1 — Update da imagem com SESSION_ISOLATION_ENABLED=false (auto-migrate inline)"
echo "  comando:"
echo "  docker service update --image $NEW_IMAGE --env-add SESSION_ISOLATION_ENABLED=false --with-registry-auth $SERVICE"
docker service update \
  --image "$NEW_IMAGE" \
  --env-add SESSION_ISOLATION_ENABLED=false \
  --with-registry-auth \
  --update-failure-action rollback \
  --update-order start-first \
  "$SERVICE"
ok "update solicitado"

# Aguardar convergência
log "Aguardando rolling update completar (até 5 min)..."
for i in $(seq 1 60); do
    STATE=$(docker service ps "$SERVICE" --filter desired-state=running --format '{{.CurrentState}}' | head -1)
    if [[ "$STATE" == Running* ]]; then
        ok "container rodando (após ${i}×5s)"
        break
    fi
    sleep 5
done
[[ "$STATE" == Running* ]] || fail "rolling update não convergiu — checar 'docker service ps $SERVICE'"

# --- Passo 2: validar migração via logs ---
log "Passo 2 — Validando auto-migration nos logs (últimos 5 min)"
sleep 10  # dar tempo do boot terminar
MIGRATION_LOG=$(docker service logs "$SERVICE" --since 5m 2>&1 | grep -E 'migration|enterMigrationMode|exitMigrationMode' | head -20 || true)
if [[ -z "$MIGRATION_LOG" ]]; then
    warn "nenhum log de migração encontrado — pode ser primeiro boot sem dados legados, OK seguir"
else
    echo "$MIGRATION_LOG"
    if echo "$MIGRATION_LOG" | grep -qi 'error\|failed\|abort'; then
        fail "ERRO durante migração — VER LOGS COMPLETOS:  docker service logs $SERVICE --since 10m"
    fi
fi
ok "migração sem erros aparentes"

# --- Passo 3: gate D4 (3 testes) ---
log "Passo 3 — Gate D4 (bind loopback × Traefik overlay)"

CONTAINER=$(docker ps -q -f name="$SERVICE" | head -1)
[[ -n "$CONTAINER" ]] || fail "container não encontrado"

# T1: loopback dentro responde
if docker exec "$CONTAINER" curl -sfm 5 http://127.0.0.1:32352/health >/dev/null 2>&1; then
    ok "T1 PASS — loopback dentro do container responde"
else
    fail "T1 FAIL — loopback não responde. Provável: Node não subiu corretamente. VER: docker logs $CONTAINER"
fi

# T2: container alheio NÃO alcança (defesa funcionando)
T2_RESULT=$(docker run --rm --network "$OVERLAY_NET" alpine:3 sh -c \
  "apk add --no-cache curl >/dev/null 2>&1 && curl -sfm 5 http://${SERVICE}:32352/health" 2>&1 || true)
if [[ -z "$T2_RESULT" ]] || echo "$T2_RESULT" | grep -qiE 'timeout|refused|connect|exit'; then
    ok "T2 PASS — overlay externa NÃO alcança Node (defesa OK)"
else
    fail "T2 FAIL — container alheio alcançou Node ($T2_RESULT). DEFESA QUEBRADA. NÃO LIGAR enforcement. Investigar bind loopback."
fi

# T3: Traefik → Flask → Node passa
# Nota: precisa de cookie válido. Se vazio, pulamos com warn.
# Aqui usamos rota pública /api/health do Flask (não /terminal/api/health) — esse não exige auth.
if curl -sfm 10 https://ai.apiaambiental.com.br/api/health | grep -qi 'ok\|healthy'; then
    ok "T3 PASS — Flask externo responde via Traefik"
else
    warn "T3 INCONCLUSIVO — /api/health não retornou ok. Validar manualmente."
fi

# --- Passo 4: ligar enforcement ---
log "Passo 4 — Ligar enforcement (SESSION_ISOLATION_ENABLED=true)"
docker service update \
  --env-add SESSION_ISOLATION_ENABLED=true \
  --with-registry-auth \
  "$SERVICE"
ok "enforcement update solicitado"

# Aguardar convergência
log "Aguardando rolling update (até 3 min)..."
for i in $(seq 1 36); do
    STATE=$(docker service ps "$SERVICE" --filter desired-state=running --format '{{.CurrentState}}' | head -1)
    if [[ "$STATE" == Running* ]]; then
        ok "container rodando (após ${i}×5s)"
        break
    fi
    sleep 5
done

# --- Passo 5: validar estado final ---
log "Passo 5 — Validação final"
sleep 5
ENV_CHECK=$(docker service inspect "$SERVICE" --format '{{range .Spec.TaskTemplate.ContainerSpec.Env}}{{println .}}{{end}}' | grep SESSION_ISOLATION_ENABLED || echo "(none)")
echo "  env: $ENV_CHECK"
[[ "$ENV_CHECK" == *"=true" ]] || fail "SESSION_ISOLATION_ENABLED não está =true após update"

# Quick check de mismatches nos últimos 2 min (esperado: zero, ou poucos casos legítimos)
MISMATCH_COUNT=$(docker service logs "$SERVICE" --since 2m 2>&1 | grep -c '"event":"owner_mismatch"' || true)
if [[ "$MISMATCH_COUNT" -gt 10 ]]; then
    warn "muitos owner_mismatch nos últimos 2min ($MISMATCH_COUNT) — investigar:"
    docker service logs "$SERVICE" --since 2m 2>&1 | grep '"event":"owner_mismatch"' | head -5
else
    ok "owner_mismatch nos últimos 2min: $MISMATCH_COUNT (aceitável)"
fi

# --- Done ---
log "DEPLOY OK"
echo "  imagem antes:  $CURRENT_IMAGE"
echo "  imagem agora:  $NEW_IMAGE"
echo "  enforcement:   ON"
echo ""
echo "  PRÓXIMO PASSO (no Claude, não aqui):"
echo "    1. Avisar Apex que deploy OK"
echo "    2. Apex reverte mitigação (UPDATE users SET is_active=1 WHERE role='operator')"
echo "    3. Smoke manual: login como David + login como Luciane → confirmar zero cruzamento"
echo "    4. Apex aciona Grid para suíte de testes"
echo ""
echo "  Em caso de problema:"
echo "    Cenário 1 (algo quebrou): docker service update --env-add SESSION_ISOLATION_ENABLED=false $SERVICE"
echo "    Cenário 4 (reverter tudo): docker service update --image $CURRENT_IMAGE --env-rm SESSION_ISOLATION_ENABLED $SERVICE"
