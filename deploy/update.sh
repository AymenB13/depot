#!/bin/bash
# Mise à jour du portail de dépôt, lancée toutes les 3 minutes par depot-update.timer.
# Ne touche qu'à /opt/depot et au projet Docker « depot ». Utilise la copie figée de compose.yaml
# et de ce script posée par install.sh : un push ne peut changer que le code de l'image.
#   update.sh            : déploie si main a changé sur GitHub (3 essais au plus par version)
#   update.sh --force    : reconstruit et redéploie quoi qu'il arrive
#   update.sh --restart  : redémarre avec le nouvel environnement, sans reconstruire
# Si la nouvelle version ne répond pas, la précédente est remise en place.
set -euo pipefail

ROOT=${DEPOT_ROOT:-/opt/depot}
SRC=$ROOT/src
IMAGE=depot-app
MAX_TRIES=3
HEALTH_TRIES=${DEPOT_HEALTH_TRIES:-45}
COMPOSE=(docker compose -p depot -f "$ROOT/compose.yaml")

MODE=${1:-}
case $MODE in
  "" | --force | --restart) ;;
  *)
    echo "Usage : update.sh [--force | --restart]" >&2
    exit 2
    ;;
esac

log() { echo "$(date -u +%FT%TZ) $*"; }

# Une seule exécution à la fois : le passage du timer cède la place, une demande manuelle attend.
exec 9>"$ROOT/.update.lock"
if [ -n "$MODE" ]; then
  flock -w 900 9 || {
    log "Une autre mise à jour est en cours : réessaie dans quelques minutes."
    exit 1
  }
else
  flock -n 9 || exit 0
fi

wait_healthy() {
  for _ in $(seq 1 "$HEALTH_TRIES"); do
    if [ "$(docker inspect -f '{{.State.Health.Status}}' depot 2>/dev/null)" = healthy ]; then
      return 0
    fi
    sleep 2
  done
  return 1
}

if [ "$MODE" = "--restart" ]; then
  "${COMPOSE[@]}" up -d --no-build --force-recreate app
  if ! wait_healthy; then
    log "Le portail ne répond pas après le redémarrage : voir docker logs --tail 50 depot"
    exit 1
  fi
  exit 0
fi

cd "$SRC"
git fetch --quiet origin main
TARGET=$(git rev-parse origin/main)
DEPLOYED=$(cat "$ROOT/deployed" 2>/dev/null || git rev-parse HEAD)
FAILED_SHA="" FAILED_COUNT=0
if [ -s "$ROOT/failed" ]; then
  read -r FAILED_SHA FAILED_COUNT < "$ROOT/failed" || true
fi
if [ "$FAILED_SHA" != "$TARGET" ] || ! [[ $FAILED_COUNT =~ ^[0-9]+$ ]]; then
  FAILED_COUNT=0
fi
if [ "$MODE" != "--force" ]; then
  [ "$TARGET" != "$DEPLOYED" ] || exit 0
  [ "$FAILED_COUNT" -lt "$MAX_TRIES" ] || exit 0
fi

# fail <raison> [final] : note l'échec ; « final » épuise les essais.
fail() {
  local count=$((FAILED_COUNT + 1))
  if [ -n "${2:-}" ]; then count=$MAX_TRIES; fi
  echo "$TARGET $count" > "$ROOT/failed"
  log "Échec du déploiement de ${TARGET:0:7} ($count/$MAX_TRIES) : $1"
  exit 1
}

git reset --quiet --hard "$TARGET"
log "Construction de ${TARGET:0:7}"
docker image tag "$IMAGE:latest" "$IMAGE:previous" 2>/dev/null || true
nice -n 10 "${COMPOSE[@]}" build --pull app || fail "construction impossible, la version en ligne ne change pas"
"${COMPOSE[@]}" up -d --remove-orphans app || fail "démarrage impossible"
if ! wait_healthy; then
  if docker image inspect "$IMAGE:previous" >/dev/null 2>&1; then
    docker image tag "$IMAGE:previous" "$IMAGE:latest"
    "${COMPOSE[@]}" up -d --no-build --force-recreate app || true
    wait_healthy || true
    fail "la nouvelle version ne répond pas, la précédente est remise en place" final
  fi
  fail "la nouvelle version ne répond pas" final
fi
echo "$TARGET" > "$ROOT/deployed"
rm -f "$ROOT/failed"
docker image prune -f --filter label=app=depot >/dev/null 2>&1 || true
log "Déployé ${TARGET:0:7}"
