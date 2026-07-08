FROM node:24-slim
WORKDIR /app
COPY package*.json ./
RUN npm install --omit=dev
COPY src ./src
COPY scripts ./scripts
COPY sources.json ./sources.json
ENV DB_PATH=/data/spam.db
VOLUME /data
EXPOSE 3000
CMD ["node", "src/server.js"]
