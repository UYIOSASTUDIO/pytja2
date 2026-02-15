# --- STAGE 1: BUILDER ---
FROM rust:1.75-slim-bookworm as builder

# 1. System-Abhängigkeiten installieren (OpenSSL, Protobuf Compiler für gRPC)
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

# 2. Arbeitsverzeichnis erstellen
WORKDIR /usr/src/app

# 3. Source Code kopieren (Nutzt .dockerignore)
COPY . .

# 4. Release Build (Maximale Optimierung -O3)
# Wir bauen Server und Admin-Tool
RUN cargo build --release -p pytja_server --bin pytja_server --bin admin

# --- STAGE 2: RUNTIME (Production) ---
FROM debian:bookworm-slim

# 1. Minimale Runtime-Libs installieren (SSL, CA-Certs)
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# 2. Sicherheits-User erstellen (Niemals als Root laufen!)
RUN useradd -m -u 1000 -U pytja_user

WORKDIR /app

# 3. Binaries aus dem Builder kopieren
COPY --from=builder /usr/src/app/target/release/pytja_server /usr/local/bin/pytja_server
COPY --from=builder /usr/src/app/target/release/admin /usr/local/bin/pytja_admin

# 4. Ordner für lokale Daten/Logs vorbereiten
RUN mkdir -p /app/data /app/logs && chown -R pytja_user:pytja_user /app

# 5. User wechseln
USER pytja_user

# 6. Ports und Environment
ENV RUST_LOG=info
EXPOSE 50051

# 7. Startbefehl
CMD ["pytja_server"]