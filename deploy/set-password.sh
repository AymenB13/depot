#!/bin/bash
# Nouveau mot de passe pour l'espace d'administration, à lancer depuis le terminal de hPanel :
#   bash /opt/depot/src/deploy/set-password.sh
# Rien ne s'affiche pendant la saisie. Le portail redémarre ensuite et les sessions ouvertes se ferment.
set -euo pipefail
umask 077

ROOT=${DEPOT_ROOT:-/opt/depot}
FILE=$ROOT/app.env

[ "$(id -u)" -eq 0 ] || {
  echo "À lancer en root." >&2
  exit 1
}

IFS= read -rsp "Nouveau mot de passe (12 caractères au moins) : " first
echo
IFS= read -rsp "Encore une fois : " second
echo
if [ "$first" != "$second" ]; then
  echo "Les deux saisies sont différentes. Rien n'a changé." >&2
  exit 1
fi
if [ ${#first} -lt 12 ]; then
  echo "12 caractères au moins. Rien n'a changé." >&2
  exit 1
fi

hash=$(printf '%s' "$first" | docker run --rm -i --network none depot-app:latest node cli.js hash-password)
{
  grep -v '^ADMIN_PASSWORD_HASH=' "$FILE" || true
  printf 'ADMIN_PASSWORD_HASH=%s\n' "$hash"
} > "$FILE.tmp"
mv "$FILE.tmp" "$FILE"
chmod 600 "$FILE"

echo "Redémarrage du portail…"
bash "$ROOT/bin/update.sh" --restart
echo "C'est fait."
