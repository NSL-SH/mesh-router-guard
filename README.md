# mesh-router-guard

Packet-level enforcement of [CrowdSec](https://github.com/crowdsecurity/crowdsec) ban decisions on a
mesh box: the CrowdSec firewall bouncer (static binary from its
[release](https://github.com/crowdsecurity/cs-firewall-bouncer/releases)) plus an entrypoint that owns
**one** nftables table, `inet nsl-guard`.

It is the enforcement half of the box's edge protection; detection is a stock `crowdsec` container
reading sshd's journal and Caddy's access log file (`MESH_ACCESS_LOG=on` in mesh-router-caddy). Both
are deployed by `mesh-router-template-root`. Design: the PCS edge-protection study
(`yundera-root/doc/study/pcs-edge-protection-study.md`, §4.2-4.3).

## What it does

```
table inet nsl-guard {
    set exempt4 / exempt6                       gateways, tunnel, backend, the box, private ranges
    set crowdsec-blacklists / crowdsec6-...     filled by the bouncer (set-only mode), with timeouts
    chain guard {
        type filter hook prerouting priority -150; policy accept;   # before Docker's DNAT
        ct direction reply accept               # replies to connections the box opened
        ip saddr @exempt4 accept
        ip6 saddr @exempt6 accept
        ip saddr @crowdsec-blacklists drop
        ip6 saddr @crowdsec6-blacklists drop
    }
}
```

- A ban drops **every port** on the direct path: sshd, 80/443 and published app ports.
- **Lockout guard:** the exempt sets are loaded in the same transaction as the drop rules, and
  checked first. No rule matches a port without a source.
- Relayed traffic (gateway, tunnel) arrives from exempt addresses: a ban never cuts it.
- Stopping the container removes the table. The bouncer exiting on its own does too (the
  restart policy brings it back).

### Exempt sources

| Source | Refreshed |
|---|---|
| Loopback and private ranges | — |
| `gatewayIps`, `tunnelProviders` hosts and the backend host, from `<backend>/router/api/version` (backend = first field of `PROVIDER_STR`) | every `GUARD_REFRESH_MINUTES`; last answer kept in `GUARD_STATE_DIR` |
| `PUBLIC_IP`, `PUBLIC_IPV6` | at start |
| `GUARD_EXEMPT` | at start |

On a first start with the backend unreachable and no saved list, **bans are not enforced**: the
guard retries every `GUARD_RETRY_SECONDS` rather than risk dropping a gateway.

## Running it

```yaml
mesh-router-guard:
  image: ghcr.io/nsl-sh/mesh-router-guard:<version>
  network_mode: host
  cap_drop: [ALL]
  cap_add: [NET_ADMIN]
  security_opt: [no-new-privileges:true]
  environment:
    - PROVIDER_STR=${PROVIDER_STR}
    - LAPI_URL=http://127.0.0.1:8089/
  volumes:
    - ./data/guard/bouncer_key:/run/secrets/bouncer_key:ro
    - ./data/guard/state:/var/lib/mesh-router-guard
```

| Variable | Default | |
|---|---|---|
| `LAPI_URL` | `http://127.0.0.1:8089/` | CrowdSec local API (the guard runs in the host netns: publish the LAPI on loopback) |
| `BOUNCER_KEY_FILE` / `BOUNCER_KEY` | `/run/secrets/bouncer_key` | The bouncer's API key, registered in CrowdSec (`BOUNCER_KEY_<name>` or a `bouncer_key*` secret) |
| `PROVIDER_STR` | — | `<backend>,<userid>,<signature>`; only the backend URL is read |
| `PUBLIC_IP`, `PUBLIC_IPV6` | — | The box's own addresses |
| `GUARD_EXEMPT` | — | Extra addresses or CIDRs, space- or comma-separated |
| `GUARD_REFRESH_MINUTES` | `30` | How often the backend's list is re-read |
| `GUARD_RETRY_SECONDS` | `30` | Retry interval while no list is known |
| `GUARD_STATE_DIR` | `/var/lib/mesh-router-guard` | Where the last backend list is kept |
| `GUARD_TABLE` | `nsl-guard` | Table name |

## Inspecting a box

```bash
sudo nft list table inet nsl-guard                 # exempt sets, ban sets, drop counters
docker exec <crowdsec> cscli decisions list        # why an address is banned
docker exec <crowdsec> cscli decisions delete --ip <ip>   # unban (gone from the set within 10 s)
```

## Release

A GitHub Action publishes `ghcr.io/nsl-sh/mesh-router-guard` (amd64, arm64) on push to `main` and
on `v*` tags (`v1.2.3` → `1.2.3`). The bouncer version is `BOUNCER_VERSION` in the Dockerfile.
