# Self-hostable dshn relay. It just installs the published, self-contained
# @dshn/relay npm package (ws + protocol inlined, zero deps) — no build toolchain.
#   docker build -t dshn-relay .
# Pin a version with --build-arg DSHN_RELAY_VERSION=0.1.2 (default: latest).
# See SELF-HOSTING.md for DNS, TLS, and how to point agents at it.
FROM node:20-slim
ARG DSHN_RELAY_VERSION=latest
RUN npm install -g @dshn/relay@${DSHN_RELAY_VERSION} && npm cache clean --force
# The data dir (claims.json + the auto-generated cookie-secret) persists on the
# volume — back it up. Nothing else needs setting except your apex.
ENV DSHN_DATA_DIR=/data
ENV DSHN_RELAY_PORT=8787
VOLUME /data
EXPOSE 8787
# Only DSHN_APEX must be supplied at run time (or pass --apex). See SELF-HOSTING.md.
ENTRYPOINT ["dshn-relay"]
