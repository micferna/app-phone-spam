# Dockerfile racine utilisé par runship (le backend vit dans backend/).
FROM node:24-slim
WORKDIR /app
COPY backend/package*.json ./
# better-sqlite3 se compile depuis les sources sous Node 24 : outils de
# build nécessaires le temps du npm install, puis retirés.
RUN apt-get update && apt-get install -y --no-install-recommends python3 make g++ \
 && npm install --omit=dev \
 && apt-get purge -y python3 make g++ && apt-get autoremove -y \
 && rm -rf /var/lib/apt/lists/*
COPY backend/src ./src
COPY backend/scripts ./scripts
COPY backend/sources.json ./sources.json
ENV DB_PATH=/data/spam.db
VOLUME /data
EXPOSE 3000
CMD ["node", "src/server.js"]
