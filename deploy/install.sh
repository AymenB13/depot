#!/bin/bash
# Installation du portail de dépôt sur le VPS, à lancer une fois en root depuis le terminal de hPanel :
#   curl -fsSL https://raw.githubusercontent.com/AymenB13/depot/main/deploy/install.sh -o /root/depot-install.sh && bash /root/depot-install.sh
#
# Ne touche qu'à /opt/depot, au projet Docker « depot » (conteneur depot, image depot-app),
# à son antivirus (conteneur depot-clamav), au routeur Traefik « depot » et aux unités systemd
# depot-update.*. Peut être relancé sans risque :
# les clés et le mot de passe déjà créés sont gardés.
set -euo pipefail
umask 077

REPO=${DEPOT_REPO:-https://github.com/AymenB13/depot.git}
ROOT=${DEPOT_ROOT:-/opt/depot}
HOST=${DEPOT_HOST:-files.aymenbenali.com}
IMAGE=depot-app
COMPOSE=(docker compose -p depot -f "$ROOT/compose.yaml")

say() { printf '\n%s\n' "$*"; }
die() {
  printf '\nArrêt : %s\n' "$*" >&2
  exit 1
}

[ "$(id -u)" -eq 0 ] || die "lance ce script en root (terminal de hPanel)."
command -v docker >/dev/null || die "Docker est introuvable."
docker compose version >/dev/null 2>&1 || die "docker compose est introuvable."
command -v git >/dev/null || die "git est introuvable."
command -v curl >/dev/null || die "curl est introuvable."
docker network inspect proxy >/dev/null 2>&1 || die "le réseau Docker « proxy » de Traefik est introuvable."

# 1. Aucun service existant ne doit porter nos noms ni répondre déjà pour HOST.
for id in $(docker ps -aq); do
  name=$(docker inspect -f '{{.Name}}' "$id" | sed 's#^/##')
  project=$(docker inspect -f '{{if .Config.Labels}}{{index .Config.Labels "com.docker.compose.project"}}{{end}}' "$id")
  [ "$project" = depot ] && continue
  case "$name" in depot | depot-clamav) die "un conteneur « $name » existe déjà et n'appartient pas au portail." ;; esac
  labels=$(docker inspect -f '{{range $k, $v := .Config.Labels}}{{$k}}={{$v}}{{println}}{{end}}' "$id")
  if printf '%s\n' "$labels" | grep -qE '^traefik\.http\.routers\.depot(-www)?\.'; then
    die "le conteneur « $name » utilise déjà un routeur Traefik « depot »."
  fi
  if printf '%s\n' "$labels" | grep '^traefik\.http\.routers\.[^.]*\.rule=' | grep -qF "$HOST"; then
    die "le conteneur « $name » répond déjà pour $HOST ou www.$HOST."
  fi
done

# 2. Le DNS doit pointer ici avant que Traefik demande le certificat à Let's Encrypt.
IPS=" $(hostname -I) "
dns_ok() {
  local ip
  for ip in $(getent ahostsv4 "$HOST" 2>/dev/null | awk '{print $1}' | sort -u); do
    case "$IPS" in *" $ip "*) return 0 ;; esac
  done
  return 1
}
if ! dns_ok; then
  say "$HOST ne pointe pas encore vers ce serveur ($(hostname -I | awk '{print $1}')). J'attends que le DNS se mette à jour (15 minutes au plus)…"
  for _ in $(seq 1 60); do
    sleep 15
    if dns_ok; then break; fi
  done
  dns_ok || die "$HOST ne pointe toujours pas vers ce serveur. Vérifie l'enregistrement DNS, puis relance la commande."
fi
say "DNS : $HOST pointe bien vers ce serveur."

# 3. Code du portail (lisible par tous : il est public ; les secrets restent dans app.env).
mkdir -p "$ROOT/bin" "$ROOT/data"
(
  umask 022
  if [ -d "$ROOT/src/.git" ]; then
    git -C "$ROOT/src" fetch --quiet origin main
    git -C "$ROOT/src" reset --quiet --hard origin/main
  else
    git clone --quiet --branch main "$REPO" "$ROOT/src"
  fi
)
# Fichiers d'exploitation figés : seule une nouvelle installation les met à jour.
install -m 644 "$ROOT/src/deploy/compose.yaml" "$ROOT/compose.yaml"
install -m 755 "$ROOT/src/deploy/update.sh" "$ROOT/bin/update.sh"
# Le conteneur tourne avec l'utilisateur 10001 : seul lui (et root) lit les données.
chown 10001:10001 "$ROOT/data"
chmod 700 "$ROOT/data"
touch "$ROOT/app.env"
chmod 600 "$ROOT/app.env"

say "Construction de l'image…"
"${COMPOSE[@]}" build --pull app

# 4. Clé de chiffrement et mot de passe : créés une seule fois, jamais écrasés.
PASSWORD=""
if ! grep -q '^MASTER_KEY=.' "$ROOT/app.env"; then
  key=$(docker run --rm --network none "$IMAGE:latest" node cli.js gen-key)
  printf 'MASTER_KEY=%s\n' "$key" >> "$ROOT/app.env"
fi
if ! grep -q '^ADMIN_PASSWORD_HASH=.' "$ROOT/app.env"; then
  PASSWORD=$(docker run --rm --network none "$IMAGE:latest" node cli.js gen-password)
  hash=$(printf '%s' "$PASSWORD" | docker run --rm -i --network none "$IMAGE:latest" node cli.js hash-password)
  printf 'ADMIN_PASSWORD_HASH=%s\n' "$hash" >> "$ROOT/app.env"
fi

# 5. Démarrage du portail et de son antivirus.
say "Démarrage du portail et de l'antivirus…"
"${COMPOSE[@]}" pull --quiet clamav
"${COMPOSE[@]}" up -d
healthy() { [ "$(docker inspect -f '{{.State.Health.Status}}' depot 2>/dev/null)" = healthy ]; }
for _ in $(seq 1 45); do
  if healthy; then break; fi
  sleep 2
done
healthy || die "le portail ne répond pas. Journal : docker logs --tail 50 depot"
git -C "$ROOT/src" rev-parse HEAD > "$ROOT/deployed"

# 6. Mises à jour automatiques du code depuis GitHub, toutes les 3 minutes.
install -m 644 "$ROOT/src/deploy/depot-update.service" /etc/systemd/system/depot-update.service
install -m 644 "$ROOT/src/deploy/depot-update.timer" /etc/systemd/system/depot-update.timer
systemctl daemon-reload
systemctl enable --now depot-update.timer >/dev/null 2>&1

# 7. Certificat HTTPS : Traefik le demande à Let's Encrypt dès que le routeur apparaît.
say "Vérification du certificat HTTPS…"
TLS=""
for _ in $(seq 1 36); do
  if curl -fsS --max-time 5 --resolve "$HOST:443:127.0.0.1" "https://$HOST/healthz" >/dev/null 2>&1; then
    TLS=ok
    break
  fi
  sleep 5
done

echo
echo "Le portail est en ligne : https://$HOST"
echo "Espace d'administration : https://$HOST/admin"
if [ -z "$TLS" ]; then
  echo "Le certificat HTTPS n'est pas encore prêt : réessaie l'adresse dans quelques minutes."
fi
if [ -n "$PASSWORD" ]; then
  echo
  echo "Mot de passe administrateur, affiché une seule fois."
  echo "Garde-le dans ton gestionnaire de mots de passe :"
  echo
  echo "    $PASSWORD"
fi
echo
echo "Changer de mot de passe : bash $ROOT/src/deploy/set-password.sh"
