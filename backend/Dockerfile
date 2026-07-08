FROM node:26-slim
WORKDIR /app
COPY package*.json ./
RUN apt-get update && apt-get install -y --no-install-recommends python3 make g++ \
 && npm install --omit=dev \
 && apt-get purge -y python3 make g++ && apt-get autoremove -y \
 && rm -rf /var/lib/apt/lists/*
COPY src ./src
COPY scripts ./scripts
COPY sources.json ./sources.json
ENV DB_PATH=/data/spam.db
VOLUME /data
EXPOSE 3000
CMD ["node", "src/server.js"]
