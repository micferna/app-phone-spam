# Dockerfile racine utilisé par runship. Backend Rust (axum) dans backend/.
# Multi-stage : build avec la toolchain complète, image finale minimale.

FROM rust:1-bookworm AS builder
WORKDIR /app
# Couche de cache des dépendances : on compile un main vide d'abord.
COPY backend/Cargo.toml backend/Cargo.lock ./
RUN mkdir src && echo 'fn main() {}' > src/main.rs \
 && cargo build --release \
 && rm -rf src target/release/deps/phone_spam_backend*
COPY backend/src ./src
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=builder /app/target/release/phone-spam-backend /usr/local/bin/phone-spam-backend
ENV DB_PATH=/data/spam.db
VOLUME /data
EXPOSE 3000
CMD ["phone-spam-backend"]
