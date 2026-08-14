# VyOS IP Blacklist Manager

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Target: VyOS 1.5](https://img.shields.io/badge/target-VyOS%201.5%20(Circinus)-green.svg)](https://vyos.io/)

A high-performance IP blacklist manager for **VyOS 1.5 (Circinus)** that fetches threat intelligence feeds and injects them directly into nftables — handling **50,000 to 200,000+ IP entries** efficiently.

## Overview

This script pulls IP blacklists from multiple threat intelligence sources, deduplicates, whitelist-filters, CIDR-collapses, and injects them into a VyOS router's firewall via a **two-tier hybrid strategy**:

| Tier | Mechanism | Purpose |
|------|-----------|---------|
| **Tier 1** | Direct nftables set injection | Live, millisecond-effective, no commit overhead |
| **Tier 2** | nft restore file + boot hook | Persists across reboots without touching VyOS config |

## How It Works

```
┌──────────────────────────────────────────────────────────────────────┐
│                         Execution Flow                               │
├──────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  1. Fetch ──► Parse ──► Deduplicate (from 8+ threat feeds)          │
│                            │                                         │
│  2. Whitelist Filter ────► Remove RFC1918, loopback, DNS, etc.      │
│                            │                                         │
│  3. CIDR Collapse ───────► Merge adjacent/overlapping prefixes      │
│                            │                                         │
│  4. VyOS Config Stub ────► One-time minimal config node (awareness) │
│                            │                                         │
│  5. Live nftables Inject ─► Atomic flush + repopulate (Tier 1)      │
│                            │                                         │
│  6. Persistence File ─────► Write nft restore script (Tier 2)       │
│                            │                                         │
│  7. Boot Hook ────────────► Idempotent postconfig boot hook          │
│                                                                      │
└──────────────────────────────────────────────────────────────────────┘
```

### Why Two Tiers?

- **VyOS commits are slow** — they rebuild the entire config tree. This script never runs `commit` except once (for the config stub).
- **nftables supports atomic batch operations** — `nft -f -` can flush and repopulate a set of 200k entries in seconds.
- **Persistence** is handled via nft restore files sourced at boot, bypassing VyOS's config tree entirely for the blacklist data.

## Supported Blacklist Sources

| Source | URL |
|--------|-----|
| Emerging Threats (Block IPs) | `rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt` |
| Tor Exit Nodes | `check.torproject.org/cgi-bin/TorBulkExitList.py` |
| BruteForceBlocker | `danger.rulez.sk/projects/bruteforceblocker/blist.php` |
| Spamhaus DROP | `www.spamhaus.org/drop/drop.lasso` |
| Spamhaus DROP IPv6 | `www.spamhaus.org/drop/dropv6.txt` |
| C.I. Army Malicious IP List | `cinsscore.com/list/ci-badguys.txt` |
| blocklist.de Attackers | `lists.blocklist.de/lists/all.txt` |
| GreenSnow | `blocklist.greensnow.co/greensnow.txt` |
| FireHOL Level 1 | `raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset` |
| AbuseIPDB (30 days) | `raw.githubusercontent.com/borestad/blocklist-abuseipdb/main/abuseipdb-s100-30d.ipv4` |
| FireHOL Level 2 | `raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level2.netset` |
| FireHOL Level 3 | `raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level3.netset` |
| Emerging Threats (Compromised) | `rules.emergingthreats.net/blockrules/compromised-ips.txt` |
| abuse.ch Feodo Tracker (Botnet C2) | `feodotracker.abuse.ch/downloads/ipblocklist.txt` |
| Binary Defense Artillery Banlist | `www.binarydefense.com/banlist.txt` |
| Custom Local Source | `http://172.16.0.250:8741/security/blocklist` |

Sources are configurable — edit the `BLACKLIST_URLS` list in the script.

### AbuseIPDB

The AbuseIPDB feed comes from
[borestad/blocklist-abuseipdb](https://github.com/borestad/blocklist-abuseipdb),
built from [AbuseIPDB](https://www.abuseipdb.com/) data — **please support them**.
At ~113 000 entries it is by far the largest source. Windows from `1d` to `90d`
are published; swap the file name in the URL to trade coverage against freshness.
Upstream recommends **30 days at most** to limit false positives, and asks that
`abuseipdb-s100-all` not be used, as it is published for statistics only.

Together the configured sources yield roughly **150 000 unique prefixes**,
collapsing to about **114 000** entries.

## Prerequisites

- **VyOS 1.5 (Circinus)** or a system with `nftables` installed
- Python **3.8+**
- Must be run as **root** or with `sudo` (to execute `nft` commands)

## Installation

```bash
# Download the script
wget https://raw.githubusercontent.com/<your-org>/vyos-ip-blacklist-manager/main/update-blacklist.py

# Make it executable
chmod +x update-blacklist.py
```

Or clone the repository:

```bash
git clone https://github.com/<your-org>/vyos-ip-blacklist-manager.git
cd vyos-ip-blacklist-manager
```

## Usage

### Quick Start (Dry Run — No Changes)

Always run with `--dry-run` first to see what will happen:

```bash
sudo ./update-blacklist.py --dry-run
```

### First Run

On first run, the script needs to create a minimal VyOS config stub. Use `--force-config-stub`:

```bash
sudo ./update-blacklist.py --force-config-stub
```

### Subsequent Updates

Once the config stub is in place, just run without flags:

```bash
sudo ./update-blacklist.py
```

### Options

| Flag | Description |
|------|-------------|
| `--dry-run` | Fetch, parse, and process IPs but make **no system changes**. Prints what would be injected. |
| `--force-config-stub` | Force re-creation of the VyOS config stub node. Needed on first run or if the network-group was deleted from the VyOS config tree. |
| `--timeout <seconds>` | HTTP timeout per URL (default: 30). Increase if your sources are slow or you're on a slow link. |
| `--no-nft-check` | Skip the `nft -c` syntax validation. Only needed on systems where the `vyos_filter` table does not exist, since `nft -c` fails there for reasons unrelated to the generated script. |

### Examples

```bash
# Quick preview
sudo ./update-blacklist.py --dry-run

# First-time setup with config stub
sudo ./update-blacklist.py --force-config-stub --timeout 60

# Regular scheduled update (e.g., via cron)
sudo ./update-blacklist.py

# With custom timeout for slow links
sudo ./update-blacklist.py --timeout 120
```

## Scheduling

Set up a cron job to update the blacklist periodically (e.g., daily at 3 AM):

```bash
sudo crontab -e
```

Add:

```cron
0 3 * * * /usr/local/bin/update-blacklist.py >> /var/log/vyos-blacklist.log 2>&1
```

Or as a systemd timer (recommended for VyOS):

```bash
# /etc/systemd/system/vyos-blacklist.service
[Unit]
Description=VyOS IP Blacklist Updater

[Service]
Type=oneshot
ExecStart=/usr/local/bin/update-blacklist.py
User=root

# /etc/systemd/system/vyos-blacklist.timer
[Unit]
Description=Daily VyOS blacklist update

[Timer]
OnCalendar=daily
Persistent=true

[Install]
WantedBy=timers.target
```

## Technical Details

### nftables Set

The script creates/manages an nftables set in the `ip vyos_filter` table:

```
N_Internet-Blacklist { type ipv4_addr; flags interval; auto-merge; }
```

The `auto-merge` flag causes the kernel to automatically merge overlapping and adjacent CIDR intervals — essentially **free CIDR aggregation at the kernel level**.

### VyOS Config Stub

VyOS expects network-groups it uses in firewall rules to be present in its config tree. The script creates a **single-entry stub** using a TEST-NET IP (`192.0.2.1/32`, per RFC 5737) as a placeholder. This:

1. Prevents VyOS from reporting "group not defined" errors in firewall rules.
2. Stops VyOS from recreating/destroying the nftables set on future commits.
3. Does **not** add the 200k IPs to the config tree (which would be slow and wasteful).

### Performance

| Operation | Scale | Expected Time |
|-----------|-------|---------------|
| Fetch & Parse | 200k entries | 10-30s (network bound) |
| Whitelist Filter | 200k entries | < 1s |
| CIDR Collapse | 200k entries | 5-15s |
| nftables Inject | 200k entries | 1-5s |
| **Total** | **200k entries** | **~30-60s** |

### Atomic Operations

- The nftables set is **flushed and repopulated in a single atomic transaction** — there is no window where the set is empty.
- The persistence file is written **atomically** via `os.replace()` (temp file → validate with `nft -c` → rename). A script that fails validation is discarded and the previous file stays in place.
- Feeds are fetched with `Accept-Encoding: gzip` and transparently decompressed, which takes the largest source from 6.1 MB to 820 KB. A server that ignores the header, or mislabels its encoding, is handled by falling back to the raw body.
- The boot hook is **idempotent** — a marker comment prevents duplicate entries.

## File Locations

| File | Purpose |
|------|---------|
| `/config/scripts/nft-sets/N_Internet-Blacklist.nft` | nftables restore script for persistence |
| `/config/scripts/vyos-postconfig-bootup.script` | Boot hook sourcing the restore script |
| `/var/log/syslog` | Log output (via syslog) |
| `sys.stdout` | Console log output (when running interactively) |

## Whitelist

The following prefixes are excluded from the blacklist:

- `192.168.0.0/16` — Private
- `10.0.0.0/8` — Private
- `172.16.0.0/12` — Private
- `169.254.0.0/16` — Link-local
- `127.0.0.0/8` — Loopback
- `8.8.8.8/32`, `8.8.4.4/32` — Google DNS
- `1.1.1.1/32`, `1.0.0.1/32` — Cloudflare DNS

**Partial overlaps are handled** — if a blacklist entry covers `10.0.0.0/24`, it is carved down to exclude `10.0.0.0/8`. The whitelist application uses `address_exclude()` for precise subnet carving.

## Logging

The script logs to two destinations:

1. **Syslog** (`/dev/log`) at `INFO` level — for system monitoring.
2. **Console** (stdout) at `DEBUG` level — for interactive runs.

Sample output:

```
2026-07-11 12:30:01 INFO     Fetching: https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt
2026-07-11 12:30:03 INFO       -> 45321 new entries (total raw: 45321)
2026-07-11 12:30:05 INFO     Fetching: https://www.spamhaus.org/drop/drop.lasso
2026-07-11 12:30:06 INFO       -> 1523 new entries (total raw: 46844)
2026-07-11 12:30:10 INFO     Converting 189234 unique raw strings to network objects...
2026-07-11 12:30:12 INFO     Raw parsed networks: 189234
2026-07-11 12:30:13 INFO     After whitelisting: 188912 networks (322 operations performed)
2026-07-11 12:30:18 INFO     After CIDR collapse: 142567 networks (4.12s)
2026-07-11 12:30:19 INFO     nftables set updated: 142567 entries in 1.84s
2026-07-11 12:30:19 INFO     Persistence file written: /config/scripts/nft-sets/N_Internet-Blacklist.nft
2026-07-11 12:30:19 INFO     Boot hook installed in /config/scripts/vyos-postconfig-bootup.script
2026-07-11 12:30:19 INFO     Done. 142567 final rules | 322 whitelisted | 18.24s total
```

## Security Considerations

- **Root execution required** — `nft` commands need elevated privileges. Review the script before running as root.
- **HTTP sources** — One source uses plain HTTP. A MITM could inject malicious IPs. Consider proxying sensitive sources through HTTPS.
- **No traffic filtering** — This script only populates an nftables set. You must configure a firewall rule that **references** the `Internet-Blacklist` network-group to actually drop traffic.
- **Boot hook risk** — If an nft restore file is malformed on boot, it could delay the firewall coming up. The script validates every generated script with `nft -c` (parse and check, no changes applied) before applying the live batch and before promoting the persistence file, so a malformed script cannot replace a working one. Use `--no-nft-check` to bypass this.

## Firewall Rule Example

To actually block traffic, add a firewall rule referencing the blacklist:

```bash
configure
set firewall name WAN-IN rule 10 action drop
set firewall name WAN-IN rule 10 source group network-group Internet-Blacklist
set firewall name WAN-IN rule 10 log enable
commit
save
```

## Troubleshooting

| Symptom | Likely Cause | Resolution |
|---------|-------------|-----------|
| `nftables injection failed` | nftables set doesn't exist | Run with `--force-config-stub` |
| `nft syntax check failed` | The `vyos_filter` table is missing, or a source returned something the generator cannot express | Check `nft list tables`; bypass with `--no-nft-check` if the table is genuinely absent |
| `Failed to fetch` | Network issue or source changed | Check connectivity, increase `--timeout` |
| `No valid IP entries found` | All sources failed or returned empty | Check source URLs and network |
| Set exists but traffic not blocked | No firewall rule references it | Add a firewall rule (see example above) |
| Blacklist not loaded after reboot | Boot hook or persistence file missing | Check `/config/scripts/nft-sets/` and boot script |

## License

MIT — see [LICENSE](LICENSE) for details.
