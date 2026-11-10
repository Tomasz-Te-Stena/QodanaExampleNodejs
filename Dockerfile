# ============================================================
# STAGE 1 - BUILD AND TEST
# ============================================================
FROM node:24-alpine AS build

WORKDIR /app

# Optional corporate CA certificate (Cisco Umbrella TLS inspection).
# The trailing * wildcard makes the COPY a no-op when the file is
# absent (e.g. on Azure Pipelines agents, where it is gitignored),
# so the same Dockerfile builds both on the corporate network and in CI.
COPY corporate-ca.crt* /usr/local/share/ca-certificates/

# Appended straight to the system bundle, because apk itself
# cannot reach the Alpine mirrors until this CA is trusted.
RUN if [ -f /usr/local/share/ca-certificates/corporate-ca.crt ]; then \
        cat /usr/local/share/ca-certificates/corporate-ca.crt >> /etc/ssl/certs/ca-certificates.crt; \
    fi

# Point Node at the full system bundle (always present, and includes
# the corporate CA when it was added above).
ENV NODE_EXTRA_CA_CERTS=/etc/ssl/certs/ca-certificates.crt

COPY package.json package-lock.json ./

RUN --mount=type=cache,target=/root/.npm \
    npm ci

# Main app file and its Jest test file. Defaults match this repo;
# Azure Pipelines overrides them with --build-arg.
ARG MAIN_FILE=server.js
ARG TEST_FILE=server.test.js

COPY ${MAIN_FILE} ${TEST_FILE} ./
COPY eslint.config.js ./

RUN npm run lint
RUN npm test -- --collectCoverageFrom="${MAIN_FILE}" --runTestsByPath "${TEST_FILE}"


# ============================================================
# STAGE 2 - RUNTIME
# ============================================================
FROM node:24-alpine AS runner

WORKDIR /app

ENV NODE_ENV=production

# The app runs with plain "node <MAIN_FILE>" and has no runtime
# dependencies, so npm/npx/corepack are not needed at runtime.
# Removing them drops their bundled packages (and their CVEs,
# e.g. in undici and brace-expansion) from the final image.
RUN rm -rf /usr/local/lib/node_modules \
           /usr/local/bin/npm \
           /usr/local/bin/npx \
           /usr/local/bin/corepack \
           /opt/yarn* \
           /usr/local/bin/yarn \
           /usr/local/bin/yarnpkg

ARG MAIN_FILE=server.js
ENV MAIN_FILE=${MAIN_FILE}

COPY --from=build --chown=node:node /app/${MAIN_FILE} ./${MAIN_FILE}

USER node

EXPOSE 8080

# Shell form is needed to expand $MAIN_FILE; "exec" makes node PID 1
# so it still receives SIGTERM from "docker stop" directly.
CMD ["sh", "-c", "exec node \"$MAIN_FILE\""]