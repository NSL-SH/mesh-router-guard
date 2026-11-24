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
| `LAPI_WAIT_SECONDS` | `120` | How long to wait for the local API before starting the bouncer anyway |
| `GUARD_STATE_DIR` | `/var/lib/mesh-router-guard` | Where the last backend list is kept |
| `GUARD_TABLE` | `nsl-guard` | Table name |

## guard-sync: the fleet list

The image also carries `guard-sync` (`cmd/guard-sync`, Go, stdlib only), run as a **separate
container** with `entrypoint: [guard-sync]`, no privileges and no host network. It is the box's link
to the NSL fleet ban list (mesh-router-backend `Guard.ts`). Every `GUARD_SYNC_MINUTES`:

1. **Report** what this box's own CrowdSec banned: alerts from `crowdsecurity/*` scenarios on a
   single address with a decision of origin `crowdsec` (imported, manual and allowlisted sources
   never qualify), as `{ip, scenario, at}` to `POST <backend>/router/api/guard/v1/reports/<userid>/<sig>`.
2. **Import** `GET <backend>/router/api/guard/v1/list/<userid>/<sig>`: fleet bans plus the public
   lists, an Ed25519-signed document. The key is pinned at first use (or must equal
   `GUARD_LIST_KEY`); a list under another key is refused. Each entry becomes a CrowdSec decision
   (origin `nsl-fleet` / `nsl-<list>`, scenario hung off an `nsl/import` alert), lasting until the
   entry's `until`: renewed when it nears its end (public lists: about every two days), deleted
   once the list drops it. **Any value an allowlist of the box overlaps is left out**: the local
   API does not check allowlists for decisions that arrive with their alert, so guard-sync does.

Decisions reach the bouncer's nft sets like local ones; nothing changes on the enforcement side.

| Variable | Default | |
|---|---|---|
| `PROVIDER_STR` | — | `<backend>,<userid>,<signature>`, the box credential |
| `LAPI_URL` | `http://crowdsec:8080/` | CrowdSec's local API, as a machine (watcher) |
| `SYNC_MACHINE` | `guard-sync` | Machine name registered in CrowdSec |
| `SYNC_PASSWORD` / `SYNC_PASSWORD_FILE` | — | Its password |
| `GUARD_SYNC_MINUTES` | `60` | Interval (+ up to 1/6 jitter), minimum 5 |
| `GUARD_REPORT` / `GUARD_IMPORT` | `on` | `off` turns either half off |
| `GUARD_LIST_KEY` | — | Pin this base64 public key instead of the first one seen |
| `GUARD_STATE_DIR` | `/var/lib/mesh-router-guard` | `sync.json`: pinned key, last report and import |

```bash
docker run --rm -v "$PWD":/src -w /src golang:1.25 go test ./...   # plan, list parsing, pinning
```

## Inspecting a box

```bash
sudo nft list table inet nsl-guard                 # exempt sets, ban sets, drop counters
docker exec <crowdsec> cscli decisions list        # why an address is banned
docker exec <crowdsec> cscli decisions delete --ip <ip>   # unban (gone from the set within 10 s)
```

## Release

A GitHub Action publishes `ghcr.io/nsl-sh/mesh-router-guard` (amd64, arm64) on push to `main` and
on `v*` tags (`v1.2.3` → `1.2.3`). The bouncer version is `BOUNCER_VERSION` in the Dockerfile.
