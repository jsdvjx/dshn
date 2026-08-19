# Self-hostable dshn relay. Multi-stage: build the bundled relay from source,
# then run it on a slim Node image. Builds from a fresh clone with no extra setup:
#   docker build -t dshn-relay .
# See SELF-HOSTING.md for DNS, TLS, and how to point agents at it.
# syntax=docker/dockerfile:1

FROM node:20-slim AS build
WORKDIR /src
RUN corepack enable
COPY . .
RUN pnpm install --frozen-lockfile && pnpm build && node scripts/build-dist.mjs

FROM node:20-slim AS run
WORKDIR /app
COPY --from=build /src/dist/relay/relay.mjs ./relay.mjs
# claims.json (subdomain → scrypt hash) persists on a volume; back it up.
ENV DSHN_CLAIMS=/data/claims.json
ENV DSHN_RELAY_PORT=8787
VOLUME /data
EXPOSE 8787
# DSHN_COOKIE_SECRET and DSHN_APEX must be supplied at run time (see SELF-HOSTING.md).
ENTRYPOINT ["node", "/app/relay.mjs"]
