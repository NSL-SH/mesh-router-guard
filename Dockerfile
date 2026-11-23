# mesh-router-guard: the CrowdSec firewall bouncer (static Go binary from its release) plus
# the entrypoint that owns the `inet nsl-guard` nft table. Runs in the host netns with
# NET_ADMIN only; see README.md.
FROM alpine:3.24
ARG BOUNCER_VERSION=v0.0.38
ARG TARGETARCH
RUN apk add --no-cache nftables curl jq musl-utils \
 && curl -fsSL "https://github.com/crowdsecurity/cs-firewall-bouncer/releases/download/${BOUNCER_VERSION}/crowdsec-firewall-bouncer-linux-${TARGETARCH:-amd64}.tgz" \
    | tar -xz -C /tmp \
 && install -m 0755 /tmp/crowdsec-firewall-bouncer-*/crowdsec-firewall-bouncer /usr/local/bin/ \
 && rm -rf /tmp/crowdsec-firewall-bouncer-*

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
