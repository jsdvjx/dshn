# Self-hostable dshn relay. It just installs the published, self-contained
# @dshn/relay npm package (ws + protocol inlined, zero deps) — no build toolchain.
#   docker build -t dshn-relay .
# Pin a version with --build-arg DSHN_RELAY_VERSION=0.1.2 (default: latest).
# See SELF-HOSTING.md for DNS, TLS, and how to point agents at it.
FROM node:20-slim
ARG DSHN_RELAY_VERSION=latest
RUN npm install -g @dshn/relay@${DSHN_RELAY_VERSION} && npm cache clean --force
# claims.json (subdomain → scrypt hash) persists on a volume; back it up.
ENV DSHN_CLAIMS=/data/claims.json
ENV DSHN_RELAY_PORT=8787
VOLUME /data
EXPOSE 8787
# DSHN_COOKIE_SECRET and DSHN_APEX must be supplied at run time (see SELF-HOSTING.md).
ENTRYPOINT ["dshn-relay"]
