# ─── Stage 1: production dependencies ──────────────────────────────────────
# sqlite3 builds a native addon; the toolchain stays out of the runtime image.
FROM node:22-alpine AS deps

WORKDIR /app
RUN apk add --no-cache python3 make g++

COPY package*.json ./
RUN npm ci --omit=dev

# ─── Stage 2: runtime ──────────────────────────────────────────────────────
FROM node:22-alpine AS runtime

WORKDIR /app
# No `apk add wget` here: node:22-alpine already ships busybox's wget applet
# at /usr/bin/wget, and `wget -q -O- <url>` - the exact invocation the
# HEALTHCHECK below uses - was confirmed against this base image before
# relying on it. Installing GNU wget on top would be a redundant layer for a
# capability the base image already has.

COPY --from=deps /app/node_modules ./node_modules
COPY . .

# /app/data holds the database; the backup directory is bind-mounted at run
# time. Everything else is read-only (see the compose entry).
RUN mkdir -p /app/data && chown -R node:node /app

USER node

ENV NODE_ENV=production
ENV PORT=4570
ENV DB_PATH=/app/data/opsidious-auth.db
ENV BACKUP_DIR=/backups

EXPOSE 4570

# /healthz is mounted in app.js before anything that touches the database
# (see the comment there), specifically so it can distinguish "the process is
# alive" from "the process is alive but the database is broken" - the second
# is exactly the case a restart should fix, and this is the only check that
# can tell the two apart from outside the container.
#
#   --start-period=10s  boot does real work before the port opens: open the
#                        database, read-or-mint the pepper and the first
#                        signing key, run one sweep and one backup pass (see
#                        server.js's start()). 10s gives that room without
#                        letting a genuinely wedged boot hide behind it.
#   --interval=30s       frequent enough that a stuck process is caught and
#                        restarted well within anyone's patience for a
#                        sign-in, not so frequent that the check itself is a
#                        noticeable load on a single-instance service.
#   --timeout=3s         /healthz does no I/O (no database, no network - see
#                        spec §6), so a healthy process answers in
#                        milliseconds; 3s only needs to absorb scheduler
#                        jitter, not real work.
#   --retries=3          one slow tick under load must not flip the container
#                        to unhealthy and trigger a restart; three consecutive
#                        misses (90s of no response) is a process that is
#                        actually stuck, not a blip.
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD wget -q -O- "http://127.0.0.1:${PORT}/healthz" || exit 1

CMD ["node", "server.js"]
