# Dockerfile racine utilisé par runship (le backend vit dans backend/).
FROM node:24-slim
WORKDIR /app
COPY backend/package*.json ./
RUN npm install --omit=dev
COPY backend/src ./src
COPY backend/scripts ./scripts
COPY backend/sources.json ./sources.json
ENV DB_PATH=/data/spam.db
VOLUME /data
EXPOSE 3000
CMD ["node", "src/server.js"]
