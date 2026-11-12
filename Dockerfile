# ============================================================
# STAGE 1 - BUILD AND TEST
# ============================================================
# Base image pinned by digest: every build uses exactly the same
# image (a re-pushed "26-alpine" tag cannot change it silently).
# Renovate keeps the digest up to date.
FROM node:26-alpine@sha256:6bd9ab43c0ec0190ca7b2d193906cb8b7edf6e7f4afa43ddeccd6452710bffb5 AS build

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

# --ignore-scripts: package install scripts (preinstall/postinstall)
# never run, so a compromised dependency cannot execute code here.
RUN --mount=type=cache,target=/root/.npm \
    npm ci --ignore-scripts

# Main app file and its Jest test file. Defaults match this repo;
# Azure Pipelines overrides them with --build-arg.
ARG MAIN_FILE=server.js
ARG TEST_FILE=server.test.js

COPY ${MAIN_FILE} ${TEST_FILE} ./
COPY eslint.config.js ./

RUN npm run lint \
    && npm test -- --collectCoverageFrom="${MAIN_FILE}" --runTestsByPath "${TEST_FILE}"

# Keep only production dependencies for the runtime image
# (prune leaves empty @scope folders behind, so remove those too).
RUN npm prune --omit=dev \
    && find node_modules -mindepth 1 -type d -empty -delete


# ============================================================
# STAGE 2 - RUNTIME
# ============================================================
FROM node:26-alpine@sha256:6bd9ab43c0ec0190ca7b2d193906cb8b7edf6e7f4afa43ddeccd6452710bffb5 AS runner

WORKDIR /app

ENV NODE_ENV=production

# The app runs with plain "node <MAIN_FILE>" (its production
# node_modules are copied from the build stage below), so the
# global npm/npx/corepack are not needed at runtime.
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

COPY --from=build --chown=node:node /app/node_modules ./node_modules
COPY --from=build --chown=node:node /app/${MAIN_FILE} ./${MAIN_FILE}

# Numeric UID:GID of the "node" user, so Kubernetes "runAsNonRoot"
# and the host can verify it is not root without resolving a name.
USER 1000:1000

EXPOSE 8080

# Lets Docker (and the pipeline's smoke-test / DAST job) know when
# the API actually answers. busybox wget ships with Alpine.
HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
    CMD ["wget", "-q", "-O", "/dev/null", "http://127.0.0.1:8080/api/current_time"]

# Node.js permission model: the process may only read files under
# /app (so path traversal to /etc/passwd etc. is blocked by Node
# itself), may not write files at all, and may not load addons or
# start workers. Network (the HTTP server) and child processes (ping)
# are allowed explicitly, because the app needs them.
#
# Shell form is needed to expand $MAIN_FILE; "exec" makes node PID 1
# so it still receives SIGTERM from "docker stop" directly.
CMD ["sh", "-c", "exec node --permission --allow-fs-read=/app --allow-net --allow-child-process \"$MAIN_FILE\""]