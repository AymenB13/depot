# Portail de dépôt : une image légère, sans dépendance npm, qui tourne sans être root.
# Aucune clé dans l'image : tout arrive par l'environnement au démarrage (voir deploy/).

FROM node:22-alpine
LABEL app=depot
ENV NODE_ENV=production PORT=8080 DATA_DIR=/data
WORKDIR /app
RUN addgroup -S -g 10001 depot && adduser -S -D -u 10001 -G depot -h /app depot
COPY package.json server.js cli.js ./
COPY lib ./lib
COPY public ./public
# Lisible par l'utilisateur du conteneur quels que soient les droits des fichiers clonés sur le VPS.
RUN chmod -R a+rX,go-w /app
USER depot
EXPOSE 8080
# Sondes toutes les 2 s au démarrage : Traefik sert le conteneur dès qu'il est « healthy ».
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --start-interval=2s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:8080/healthz').then((r) => process.exit(r.ok ? 0 : 1)).catch(() => process.exit(1))"
CMD ["node", "server.js"]
