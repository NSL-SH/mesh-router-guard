# mesh-router-guard: the CrowdSec firewall bouncer (static Go binary from its release) plus
# the entrypoint that owns the `inet nsl-guard` nft table. Runs in the host netns with
# NET_ADMIN only; see README.md.
#
# The same image carries guard-sync (cmd/guard-sync), run as its own container with
# `entrypoint: [guard-sync]`: the fleet list importer and alert reporter, no privileges.
# BuildKit sets BUILDPLATFORM; a legacy `docker build` needs --build-arg BUILDPLATFORM=linux/amd64.
ARG BUILDPLATFORM
FROM --platform=$BUILDPLATFORM golang:1.25-alpine AS sync
ARG TARGETARCH
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
RUN CGO_ENABLED=0 GOARCH=${TARGETARCH:-amd64} go build -trimpath -ldflags="-s -w" -o /guard-sync ./cmd/guard-sync

FROM alpine:3.24
ARG BOUNCER_VERSION=v0.0.38
ARG TARGETARCH
RUN apk add --no-cache nftables curl jq musl-utils \
 && curl -fsSL "https://github.com/crowdsecurity/cs-firewall-bouncer/releases/download/${BOUNCER_VERSION}/crowdsec-firewall-bouncer-linux-${TARGETARCH:-amd64}.tgz" \
    | tar -xz -C /tmp \
 && install -m 0755 /tmp/crowdsec-firewall-bouncer-*/crowdsec-firewall-bouncer /usr/local/bin/ \
 && rm -rf /tmp/crowdsec-firewall-bouncer-*

COPY --from=sync /guard-sync /usr/local/bin/guard-sync
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
