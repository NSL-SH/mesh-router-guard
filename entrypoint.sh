#!/bin/sh
# mesh-router-guard: enforces CrowdSec's ban decisions on the box, at the packet level.
#
# It owns ONE nft table, `inet nsl-guard`, and touches nothing else (not Docker's chains,
# not the host's own rules). The CrowdSec firewall bouncer runs in set-only mode: it only
# fills the two ban sets. The table, the exempt sets and the rules are written here, so:
#
#   - exempt sources are accepted before any ban is looked up, and the exempt sets are
#     loaded in the same transaction as the drop rules: no instant exists where a ban
#     applies to a gateway, the tunnel relay or the box itself (the lockout guard);
#   - no rule matches a port without a source: nothing here can close a port for everyone;
#   - replies to connections the box opened are never dropped (an apt mirror or an API
#     that lands on a list keeps working), only traffic a banned source originates.
#
# Hooked at prerouting, priority -150, before Docker's DNAT (-100): a ban covers sshd,
# 80/443 and every published app port alike. It applies to the direct path only; relayed
# traffic arrives from the gateways and the tunnel, which are exempt.
#
# EXEMPT SOURCES
#   - loopback and private ranges (containers, LAN);
#   - the backend's gateways and tunnel providers (`gatewayIps`, `tunnelProviders` in
#     <backend>/router/api/version, backend = first field of PROVIDER_STR) and the
#     backend host itself, re-read every GUARD_REFRESH_MINUTES;
#   - PUBLIC_IP / PUBLIC_IPV6 (the box) and GUARD_EXEMPT (operator additions).
#   The backend's part is kept in GUARD_STATE_DIR. With neither an answer nor a saved
#   list (a first start with the backend down), the ban sets are NOT enforced: the guard
#   waits and retries rather than risk dropping a gateway. Detection goes on meanwhile.
#
# Stopping the container removes the table: no host leftover, no ban outliving the guard.
set -euf   # -f: no globbing; address lists are split on purpose, never expanded

TABLE="${GUARD_TABLE:-nsl-guard}"
LAPI_URL="${LAPI_URL:-http://127.0.0.1:8089/}"
KEY_FILE="${BOUNCER_KEY_FILE:-/run/secrets/bouncer_key}"
STATE_DIR="${GUARD_STATE_DIR:-/var/lib/mesh-router-guard}"
REFRESH_MINUTES="${GUARD_REFRESH_MINUTES:-30}"
RETRY_SECONDS="${GUARD_RETRY_SECONDS:-30}"
CONFIG=/tmp/crowdsec-firewall-bouncer.yaml
BACKEND_LIST="$STATE_DIR/backend-exempt.list"

BASE_EXEMPT="127.0.0.0/8 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 100.64.0.0/10 169.254.0.0/16 ::1 fc00::/7 fe80::/10"

# stderr: log lines must never land in a captured address list.
log() { echo "[guard] $*" >&2; }

# backend_sources: the backend's gateways, tunnel providers and own host, one address per
# line; fails when the backend cannot be asked or does not answer.
backend_sources() {
    local backend body host
    [ -n "${PROVIDER_STR:-}" ] || return 1
    backend="${PROVIDER_STR%%,*}"
    body=$(curl -sf --max-time 10 "${backend%/}/router/api/version") || return 1
    printf '%s' "$body" | jq -e '.gatewayIps | type == "array"' >/dev/null 2>&1 || return 1
    {
        printf '%s' "$body" | jq -r '.gatewayIps[]'
        # tunnelProviders are URLs (https://<host>:<port>); keep the host.
        printf '%s' "$body" | jq -r '.tunnelProviders // [] | .[]' |
            sed -E 's#^[a-z]+://##; s#/.*$##; s#^\[([^]]+)\].*#\1#; s#:[0-9]+$##'
        host=$(printf '%s' "$backend" | sed -E 's#^[a-z]+://##; s#[:/].*$##')
        printf '%s\n' "$host"
    } | while read -r h; do
        [ -n "$h" ] || continue
        if valid_addr "$h"; then echo "$h"; else getent ahosts "$h" 2>/dev/null | awk '{print $1}'; fi
    done | sort -u
}

# valid_addr: an IPv4/IPv6 address or CIDR, nothing else reaches nft.
valid_addr() {
    printf '%s' "$1" | grep -Eq '^([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?$|^[0-9A-Fa-f:]*:[0-9A-Fa-f:.]*(/[0-9]{1,3})?$'
}

# exempt_list: every exempt source, one per line. Fails when the backend's part is unknown.
exempt_list() {
    local fresh
    mkdir -p "$STATE_DIR"
    if fresh=$(backend_sources) && [ -n "$fresh" ]; then
        printf '%s\n' "$fresh" >"$BACKEND_LIST.tmp" && mv "$BACKEND_LIST.tmp" "$BACKEND_LIST"
    elif [ -s "$BACKEND_LIST" ]; then
        log "WARN: backend gateway list unavailable, using the saved one"
    else
        return 1
    fi
    {
        cat "$BACKEND_LIST"
        printf '%s\n' $BASE_EXEMPT ${PUBLIC_IP:-} ${PUBLIC_IPV6:-} $(printf '%s' "${GUARD_EXEMPT:-}" | tr ',' ' ')
    } | while read -r a; do valid_addr "$a" && echo "$a"; done | sort -u
}

# family <4|6> <list>: that family's entries, comma-separated.
family() {
    if [ "$1" = 6 ]; then printf '%s\n' "$2" | grep ':'; else printf '%s\n' "$2" | grep -v ':'; fi | paste -sd, -
}

load_table() {  # load_table <list>: the whole table, exempt sets and rules, in one transaction
    local v4 v6
    v4=$(family 4 "$1"); v6=$(family 6 "$1")
    nft -f - <<NFT
table inet $TABLE
delete table inet $TABLE
table inet $TABLE {
    set exempt4 { type ipv4_addr; flags interval; auto-merge; ${v4:+elements = { $v4 }} }
    set exempt6 { type ipv6_addr; flags interval; auto-merge; ${v6:+elements = { $v6 }} }
    set crowdsec-blacklists { type ipv4_addr; flags timeout; }
    set crowdsec6-blacklists { type ipv6_addr; flags timeout; }
    chain guard {
        type filter hook prerouting priority -150; policy accept;
        ct direction reply accept
        ip saddr @exempt4 accept
        ip6 saddr @exempt6 accept
        ip saddr @crowdsec-blacklists counter drop
        ip6 saddr @crowdsec6-blacklists counter drop
    }
}
NFT
    log "table inet $TABLE loaded; exempt: $(printf '%s' "$1" | tr '\n' ' ')"
}

replace_exempt() {  # replace_exempt <list>: swap the exempt sets, bans untouched
    local v4 v6
    v4=$(family 4 "$1"); v6=$(family 6 "$1")
    nft -f - <<NFT
flush set inet $TABLE exempt4
flush set inet $TABLE exempt6
${v4:+add element inet $TABLE exempt4 { $v4 }}
${v6:+add element inet $TABLE exempt6 { $v6 }}
NFT
    log "exempt sources updated: $(printf '%s' "$1" | tr '\n' ' ')"
}

write_config() {
    local key
    if [ -n "${BOUNCER_KEY:-}" ]; then key="$BOUNCER_KEY"; else key=$(cat "$KEY_FILE"); fi
    umask 077
    cat >"$CONFIG" <<CFG
mode: nftables
update_frequency: 10s
log_mode: stdout
log_level: info
api_url: $LAPI_URL
api_key: $key
disable_ipv6: false
deny_action: DROP
supported_decisions_types:
  - ban
blacklists_ipv4: crowdsec-blacklists
blacklists_ipv6: crowdsec6-blacklists
nftables:
  ipv4:
    enabled: true
    set-only: true
    table: $TABLE
    chain: guard
  ipv6:
    enabled: true
    set-only: true
    table: $TABLE
    chain: guard
CFG
}

BOUNCER_PID=
REFRESH_PID=
cleanup() {
    [ -n "$REFRESH_PID" ] && kill "$REFRESH_PID" 2>/dev/null
    [ -n "$BOUNCER_PID" ] && kill "$BOUNCER_PID" 2>/dev/null && wait "$BOUNCER_PID" 2>/dev/null
    nft delete table inet "$TABLE" 2>/dev/null && log "table inet $TABLE removed"
    exit 0
}
trap cleanup TERM INT

until LIST=$(exempt_list); do
    log "WARN: no gateway list yet (backend unreachable, none saved): bans not enforced, retrying in ${RETRY_SECONDS}s"
    sleep "$RETRY_SECONDS" & wait $! || true
done
load_table "$LIST"
write_config

# The local API usually starts after this container (same stack, slower to boot). Wait
# for it, so the bouncer's first request is not a refused connection that exits it and
# restarts the container. Bounded: after LAPI_WAIT_SECONDS the bouncer starts anyway and
# the restart policy takes over.
i=0
until curl -s -o /dev/null --max-time 3 "$LAPI_URL" || [ "$i" -ge "${LAPI_WAIT_SECONDS:-120}" ]; do
    [ "$i" -eq 0 ] && log "waiting for the local API at $LAPI_URL"
    sleep 3 & wait $! || true
    i=$((i + 3))
done

(
    trap - TERM INT
    while sleep $((REFRESH_MINUTES * 60)); do
        if NEW=$(exempt_list) && [ "$NEW" != "$LIST" ]; then
            replace_exempt "$NEW" && LIST="$NEW"
        fi
    done
) &
REFRESH_PID=$!

crowdsec-firewall-bouncer -c "$CONFIG" &
BOUNCER_PID=$!
wait "$BOUNCER_PID" || true
# The bouncer exited on its own (LAPI unreachable at start, crash): remove the table rather
# than leave bans no one manages; the restart policy brings everything back.
BOUNCER_PID=
log "bouncer exited"
cleanup
