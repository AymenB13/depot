# Dépôt de documents · files.aymenbenali.com

Portail où les clients d'Aymen Benali déposent leurs fichiers. Chaque client reçoit un lien personnel qui
permet seulement de déposer ; seul l'espace d'administration (`/admin`, mot de passe) permet de télécharger.

- Fichiers chiffrés à l'arrivée (AES-256-GCM, une clé par fichier, noms compris), supprimés après 90 jours.
- Node.js 22, aucune dépendance. Conteneur sans privilèges, en lecture seule, derrière le Traefik du VPS.

## Installation (une fois, en root, depuis le terminal de hPanel)

Après avoir ajouté l'enregistrement DNS `files` vers l'IP du VPS :

    curl -fsSL https://raw.githubusercontent.com/AymenB13/depot/main/deploy/install.sh -o /root/depot-install.sh && bash /root/depot-install.sh

Le script affiche le mot de passe de l'administration une seule fois. Il ne touche qu'à `/opt/depot`,
au projet Docker `depot`, au routeur Traefik `depot` et aux unités `depot-update.*`.

## Ensuite

- Un push sur `main` est en ligne dans les 3 minutes (`depot-update.timer`).
- Nouveau mot de passe : `bash /opt/depot/src/deploy/set-password.sh`
- Journal : `docker logs --tail 100 depot` ; mises à jour : `journalctl -u depot-update --since today`
- Tests : `node --test test/*.test.js`
