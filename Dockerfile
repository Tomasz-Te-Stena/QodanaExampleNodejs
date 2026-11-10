# ============================================================
# STAGE 1 - BUILD AND TEST
# ============================================================
FROM node:24-alpine AS build

WORKDIR /app

# Add corporate CA certificate (Cisco Umbrella TLS inspection).
# Appended straight to the system bundle, because apk itself
# cannot reach the Alpine mirrors until this CA is trusted.
COPY corporate-ca.crt /usr/local/share/ca-certificates/corporate-ca.crt

RUN cat /usr/local/share/ca-certificates/corporate-ca.crt >> /etc/ssl/certs/ca-certificates.crt

# Also explicitly tell Node about it.
ENV NODE_EXTRA_CA_CERTS=/usr/local/share/ca-certificates/corporate-ca.crt

COPY package.json package-lock.json ./

RUN --mount=type=cache,target=/root/.npm \
    npm ci

COPY server.js server.test.js ./
COPY eslint.config.js ./

RUN npm run lint
RUN npm test


# ============================================================
# STAGE 2 - RUNTIME
# ============================================================
FROM node:24-alpine AS runner

WORKDIR /app

ENV NODE_ENV=production

COPY --from=build --chown=node:node /app/server.js ./server.js

USER node

EXPOSE 8080

CMD ["node", "server.js"]