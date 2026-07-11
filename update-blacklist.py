#!/usr/bin/env python3
"""
VyOS 1.5 (Circinus) High-Performance IP Blacklist Manager
==========================================================
Strategy: Two-tier hybrid injection
  - Tier 1: Direct nftables set manipulation (live, milliseconds, no commit overhead)
  - Tier 2: nft restore file + postconfig boot hook (persistence across reboots)

The VyOS config tree gets ONE lightweight stub node so VyOS remains aware of the
network-group and doesn't accidentally purge the nftables set on future commits.

Handles 50,000-200,000+ IP entries efficiently.

Usage:
  sudo python3 vyos_blacklist_optimized.py [--dry-run] [--force-config-stub]
"""

import argparse
import ipaddress
import logging
import logging.handlers
import os
import re
import subprocess
import sys
import tempfile
import time
import urllib.request
from typing import Iterator

# -- CONFIGURATION ------------------------------------------------------------

NETWORK_GROUP_NAME = "Internet-Blacklist"

# nftables set name VyOS 1.5 derives from the network-group name:
#   prefix "N_" + group name (spaces -> underscores)
NFT_SET_NAME = f"N_{NETWORK_GROUP_NAME.replace(' ', '_')}"
NFT_TABLE    = "ip vyos_filter"

# Where to persist the set so it survives reboots
NFT_PERSIST_FILE   = f"/config/scripts/nft-sets/{NFT_SET_NAME}.nft"
BOOTUP_HOOK_SCRIPT = "/config/scripts/vyos-postconfig-bootup.script"
BOOTUP_HOOK_MARKER = f"# vyos-blacklist:{NFT_SET_NAME}"  # sentinel for idempotent hook injection

BLACKLIST_URLS = [
    "https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt",
    "https://check.torproject.org/cgi-bin/TorBulkExitList.py?ip=1.1.1.1", # TOR Exit Nodes
    "https://danger.rulez.sk/projects/bruteforceblocker/blist.php", # BruteForceBlocker IP List
    "https://www.spamhaus.org/drop/drop.lasso", # Spamhaus Don't Route Or Peer List (DROP)
    "https://www.spamhaus.org/drop/dropv6.txt", # Spamhaus Don't Route Or Peer List IPv6 (DROPv6)
    "https://cinsscore.com/list/ci-badguys.txt", # C.I. Army Malicious IP List
    "https://lists.blocklist.de/lists/all.txt", # blocklist.de attackers
    "https://blocklist.greensnow.co/greensnow.txt", # GreenSnow
    "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset", # Firehol Level 1
    "http://172.16.0.250:8741/security/blocklist"
]

WHITELIST = [
    "192.168.0.0/16",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "169.254.0.0/16",   # link-local
    "127.0.0.0/8",      # loopback
    "8.8.8.8/32",
    "8.8.4.4/32",
    "1.1.1.1/32",
    "1.0.0.1/32",
]

# -- LOGGING ------------------------------------------------------------------

logger = logging.getLogger("VyOS-Blacklist")
logger.setLevel(logging.DEBUG)

_syslog = logging.handlers.SysLogHandler(address="/dev/log")
_syslog.setLevel(logging.INFO)
_syslog.setFormatter(logging.Formatter("%(name)s[%(process)d]: %(levelname)s: %(message)s"))
logger.addHandler(_syslog)

_console = logging.StreamHandler(sys.stdout)
_console.setLevel(logging.DEBUG)
_console.setFormatter(logging.Formatter("%(asctime)s %(levelname)-8s %(message)s", "%Y-%m-%d %H:%M:%S"))
logger.addHandler(_console)

# -- ARGUMENT PARSING ---------------------------------------------------------

def parse_arguments() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Fetch, optimise, and inject IP blacklists into VyOS 1.5 via nftables."
    )
    p.add_argument("--dry-run", action="store_true",
                   help="Fetch and process; print what would happen but make no changes.")
    p.add_argument("--force-config-stub", action="store_true",
                   help="Force re-creation of the VyOS config stub node (needed on first run "
                        "or if the network-group was deleted from the config tree).")
    p.add_argument("--timeout", type=int, default=30,
                   help="HTTP timeout per URL in seconds (default: 30).")
    return p.parse_args()

# -- NETWORK PARSING -----------------------------------------------------------

# Pre-compiled: matches an IPv4 address or CIDR prefix at the start of a line.
_IP_RE = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?)")

def _iter_networks_from_text(text: str) -> Iterator[ipaddress.IPv4Network]:
    """Yield valid IPv4Network objects from raw text (comments, hostnames ignored)."""
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", ";", "//")):
            continue
        m = _IP_RE.match(line)
        if not m:
            continue
        try:
            yield ipaddress.ip_network(m.group(1), strict=False)
        except ValueError:
            pass

def fetch_and_parse(urls: list[str], timeout: int = 30) -> list[ipaddress.IPv4Network]:
    """
    Fetch all URLs and return a deduplicated list of IPv4Network objects.

    Memory note: raw strings are deduplicated in a set() before object creation,
    which is significantly cheaper than building a set of network objects.
    """
    raw_strings: set[str] = set()

    for url in urls:
        logger.info("Fetching: %s", url)
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "VyOS-Blacklist-Bot/2.0"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                text = resp.read().decode("utf-8", errors="ignore")
            before = len(raw_strings)
            for net in _iter_networks_from_text(text):
                raw_strings.add(str(net))
            logger.info("  -> %d new entries (total raw: %d)", len(raw_strings) - before, len(raw_strings))
        except Exception as exc:
            logger.error("Failed to fetch %s: %s", url, exc)

    if not raw_strings:
        return []

    logger.info("Converting %d unique raw strings to network objects...", len(raw_strings))
    networks: list[ipaddress.IPv4Network] = []
    for s in raw_strings:
        try:
            networks.append(ipaddress.ip_network(s, strict=False))
        except ValueError:
            pass
    return networks

# -- WHITELIST APPLICATION -----------------------------------------------------

def apply_whitelist(
    blacklist: list[ipaddress.IPv4Network],
    whitelist_strings: list[str],
) -> tuple[list[ipaddress.IPv4Network], int]:
    """
    Remove or carve whitelist prefixes out of the blacklist.

    Returns (filtered_networks, count_of_whitelisted_matches).

    Performance: O(B x W) where B = blacklist size, W = whitelist size.
    W is typically tiny (< 20 entries), so this is effectively O(B).
    """
    whitelist: list[ipaddress.IPv4Network] = []
    for s in whitelist_strings:
        try:
            whitelist.append(ipaddress.ip_network(s, strict=False))
        except ValueError:
            logger.warning("Invalid whitelist entry ignored: %s", s)

    filtered: list[ipaddress.IPv4Network] = []
    whitelisted_count = 0

    for bl_net in blacklist:
        remainder = [bl_net]
        for wl_net in whitelist:
            next_remainder: list[ipaddress.IPv4Network] = []
            for piece in remainder:
                if piece.subnet_of(wl_net):
                    # Entirely inside whitelist - drop it
                    whitelisted_count += 1
                elif piece.overlaps(wl_net):
                    # Partial overlap - carve out the whitelisted portion
                    next_remainder.extend(piece.address_exclude(wl_net))
                    whitelisted_count += 1
                else:
                    next_remainder.append(piece)
            remainder = next_remainder
        filtered.extend(remainder)

    return filtered, whitelisted_count

# -- NFTABLES DIRECT INJECTION (TIER 1: LIVE) ---------------------------------

def _nft_run(args: list[str], input_text: str | None = None) -> subprocess.CompletedProcess:
    """Run an nft command, return CompletedProcess. Raises RuntimeError on failure."""
    cmd = ["nft"] + args
    result = subprocess.run(
        cmd,
        input=input_text,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return result

def _set_exists() -> bool:
    """Check whether the nftables set already exists."""
    r = _nft_run(["list", "set"] + NFT_TABLE.split() + [NFT_SET_NAME])
    return r.returncode == 0

def _ensure_set_exists() -> None:
    """
    Create the nftables set if it doesn't exist.
    The set type matches what VyOS 1.5 uses for network-groups:
        type ipv4_addr; flags interval; auto-merge;
    auto-merge causes the kernel to merge overlapping/adjacent intervals
    automatically - essentially free CIDR aggregation at the kernel level.
    """
    if _set_exists():
        return
    logger.info("nftables set %s not found; creating...", NFT_SET_NAME)
    r = _nft_run([
        "add", "set"] + NFT_TABLE.split() + [
        NFT_SET_NAME,
        "{ type ipv4_addr; flags interval; auto-merge; }"
    ])
    if r.returncode != 0:
        raise RuntimeError(f"Failed to create nftables set: {r.stderr.strip()}")

def _build_nft_flush_add(networks: list[ipaddress.IPv4Network]) -> str:
    """
    Build a single nft batch script that atomically flushes and repopulates the set.

    Using a single 'nft -f -' transaction keeps the firewall in a consistent
    state - there is no window where the set is empty.
    """
    lines = [
        f"flush set {NFT_TABLE} {NFT_SET_NAME}",
        f"add element {NFT_TABLE} {NFT_SET_NAME} {{",
    ]
    # nft element lists: "a.b.c.d/p, ..." - we batch 500 per add statement
    # to avoid hitting kernel netlink message size limits on huge lists.
    BATCH_SIZE = 500
    for i in range(0, len(networks), BATCH_SIZE):
        chunk = networks[i : i + BATCH_SIZE]
        element_list = ", ".join(str(n) for n in chunk)
        lines.append(f"  {element_list},")
    lines.append("}")
    return "\n".join(lines) + "\n"

def inject_nftables(networks: list[ipaddress.IPv4Network], dry_run: bool = False) -> None:
    """Atomically replace the nftables set contents (live, no commit required)."""
    t0 = time.monotonic()
    logger.info("Preparing nftables batch for %d networks...", len(networks))

    nft_script = _build_nft_flush_add(networks)

    if dry_run:
        preview_lines = nft_script.splitlines()[:20]
        logger.info("[DRY-RUN] nft script preview (%d total lines):\n%s",
                    len(nft_script.splitlines()), "\n".join(preview_lines))
        if len(nft_script.splitlines()) > 20:
            logger.info("[DRY-RUN] ... (truncated)")
        return

    _ensure_set_exists()

    r = _nft_run(["-f", "-"], input_text=nft_script)
    elapsed = time.monotonic() - t0

    if r.returncode == 0:
        logger.info("nftables set updated: %d entries in %.2fs", len(networks), elapsed)
    else:
        logger.error("nftables injection failed (%.2fs):\n%s", elapsed, r.stderr.strip())
        # Don't sys.exit here - we still want to try writing the persistence file
        raise RuntimeError(f"nft batch failed: {r.stderr.strip()}")

# -- PERSISTENCE (TIER 2: REBOOT SURVIVAL) -------------------------------------

def write_persistence_file(
    networks: list[ipaddress.IPv4Network],
    dry_run: bool = False,
) -> None:
    """
    Write an nft restore file that VyOS will re-apply after boot.

    File format: a complete 'nft -f' compatible script that adds the set
    (if missing) and populates it.  Placed in /config/scripts/nft-sets/
    which is part of the VyOS config partition and survives upgrades.
    """
    set_dir = os.path.dirname(NFT_PERSIST_FILE)

    # The restore script must handle the case where the set doesn't exist yet
    # (first boot after fresh VyOS install) and where it already does.
    lines = [
        "#!/usr/sbin/nft -f",
        "# Auto-generated by vyos_blacklist_optimized.py - do not edit manually.",
        f"# Generated: {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}",
        f"# Entries: {len(networks)}",
        "",
        f"add set {NFT_TABLE} {NFT_SET_NAME} {{ type ipv4_addr; flags interval; auto-merge; }}",
        f"flush set {NFT_TABLE} {NFT_SET_NAME}",
        f"add element {NFT_TABLE} {NFT_SET_NAME} {{",
    ]
    BATCH_SIZE = 500
    for i in range(0, len(networks), BATCH_SIZE):
        chunk = networks[i : i + BATCH_SIZE]
        lines.append("  " + ", ".join(str(n) for n in chunk) + ",")
    lines.append("}")
    content = "\n".join(lines) + "\n"

    if dry_run:
        logger.info("[DRY-RUN] Would write persistence file to: %s (%d bytes)",
                    NFT_PERSIST_FILE, len(content))
        return

    os.makedirs(set_dir, mode=0o755, exist_ok=True)

    # Write atomically via a temp file in the same directory
    fd, tmp_path = tempfile.mkstemp(dir=set_dir, prefix=".tmp_")
    try:
        with os.fdopen(fd, "w") as fh:
            fh.write(content)
        os.chmod(tmp_path, 0o644)
        os.replace(tmp_path, NFT_PERSIST_FILE)
        logger.info("Persistence file written: %s", NFT_PERSIST_FILE)
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def install_boot_hook(dry_run: bool = False) -> None:
    """
    Idempotently add a line to the VyOS postconfig bootup script so that
    our nft restore file is applied after VyOS finishes its own commit on boot.

    The hook is gated on the BOOTUP_HOOK_MARKER sentinel so re-running this
    script never duplicates the line.
    """
    hook_line = f'nft -f "{NFT_PERSIST_FILE}"  {BOOTUP_HOOK_MARKER}\n'

    if dry_run:
        logger.info("[DRY-RUN] Would install boot hook in: %s", BOOTUP_HOOK_SCRIPT)
        return

    # Read existing content if the file already exists
    existing = ""
    if os.path.exists(BOOTUP_HOOK_SCRIPT):
        with open(BOOTUP_HOOK_SCRIPT, "r") as fh:
            existing = fh.read()

    if BOOTUP_HOOK_MARKER in existing:
        logger.info("Boot hook already present in %s", BOOTUP_HOOK_SCRIPT)
        return

    os.makedirs(os.path.dirname(BOOTUP_HOOK_SCRIPT), exist_ok=True)

    with open(BOOTUP_HOOK_SCRIPT, "a") as fh:
        if existing and not existing.endswith("\n"):
            fh.write("\n")
        fh.write(hook_line)

    os.chmod(BOOTUP_HOOK_SCRIPT, 0o755)
    logger.info("Boot hook installed in %s", BOOTUP_HOOK_SCRIPT)


# -- VYOS CONFIG STUB (one-time, lightweight) ----------------------------------

def _config_stub_exists(group_name: str) -> bool:
    """
    Quick check: does VyOS know about this network-group at all?
    We just inspect the live config - no commit needed.
    """
    r = subprocess.run(
        ["sg", "vyattacfg", "-c",
         f'/bin/bash -c "source /opt/vyatta/etc/functions/script-template && '
         f'cli-shell-api existsActive resources group network-group {group_name}"'],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    return r.returncode == 0


def create_config_stub(group_name: str, dry_run: bool = False) -> None:
    """
    Create a MINIMAL one-network-entry stub in the VyOS config tree.

    This ensures VyOS is aware the network-group exists so:
      1. It can be referenced in firewall rules without "group not defined" errors.
      2. VyOS doesn't recreate/destroy the nftables set on next commit.

    We put a single meaningless RFC5737 documentation IP (192.0.2.0/32) as the
    placeholder - it will never match real traffic and won't appear in our
    nftables set (which is managed directly).

    This stub is created ONCE.  Subsequent blacklist updates only touch nftables.
    """
    STUB_IP = "192.0.2.1/32"  # TEST-NET-1, RFC 5737

    if dry_run:
        logger.info("[DRY-RUN] Would create VyOS config stub for network-group '%s'.", group_name)
        return

    logger.info("Creating VyOS config stub for network-group '%s'...", group_name)
    batch = (
        "#!/bin/vbash\n"
        "source /opt/vyatta/etc/functions/script-template\n"
        "configure\n"
        f"set resources group network-group {group_name} network {STUB_IP}\n"
        "commit\n"
        "save\n"
        "exit\n"
    )
    fd, script_path = tempfile.mkstemp(suffix=".sh", prefix="vyos_stub_")
    try:
        with os.fdopen(fd, "w") as fh:
            fh.write(batch)
        os.chmod(script_path, 0o755)
        r = subprocess.run(
            ["sg", "vyattacfg", "-c", script_path],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        if r.returncode == 0:
            logger.info("Config stub committed successfully.")
        else:
            logger.error("Config stub commit failed:\n%s", r.stderr)
    finally:
        try:
            os.unlink(script_path)
        except OSError:
            pass


# -- MAIN ----------------------------------------------------------------------

def main() -> None:
    args = parse_arguments()
    t_start = time.monotonic()

    # -- 1. Fetch & Parse ----------------------------------------------------
    raw_networks = fetch_and_parse(BLACKLIST_URLS, timeout=args.timeout)
    if not raw_networks:
        logger.error("No valid IP entries found across all sources. Aborting.")
        sys.exit(1)
    logger.info("Raw parsed networks: %d", len(raw_networks))

    # -- 2. Whitelist Filtering -----------------------------------------------
    filtered, wl_count = apply_whitelist(raw_networks, WHITELIST)
    logger.info("After whitelisting: %d networks (%d operations performed)", len(filtered), wl_count)

    # -- 3. CIDR Collapse / Optimise -----------------------------------------
    logger.info("Collapsing/merging CIDR prefixes (this may take a moment for large sets)...")
    t_collapse = time.monotonic()
    optimized = list(ipaddress.collapse_addresses(filtered))
    logger.info("After CIDR collapse: %d networks (%.2fs)", len(optimized), time.monotonic() - t_collapse)

    # -- 4. Ensure VyOS Config Stub Exists ------------------------------------
    # Only runs if --force-config-stub is set OR the group doesn't exist yet.
    if args.force_config_stub or (not args.dry_run and not _config_stub_exists(NETWORK_GROUP_NAME)):
        create_config_stub(NETWORK_GROUP_NAME, dry_run=args.dry_run)
    else:
        logger.debug("VyOS config stub already present; skipping stub commit.")

    # -- 5. Live nftables Injection (Tier 1) ----------------------------------
    try:
        inject_nftables(optimized, dry_run=args.dry_run)
    except RuntimeError as exc:
        logger.critical("Live nftables injection failed: %s", exc)
        # Still write persistence file so next boot loads the correct set
        logger.warning("Continuing to write persistence file despite live injection failure.")

    # -- 6. Write Persistence File (Tier 2) -----------------------------------
    try:
        write_persistence_file(optimized, dry_run=args.dry_run)
    except Exception as exc:
        logger.error("Failed to write persistence file: %s", exc)

    # -- 7. Install Boot Hook (idempotent) ------------------------------------
    try:
        install_boot_hook(dry_run=args.dry_run)
    except Exception as exc:
        logger.error("Failed to install boot hook: %s", exc)

    # -- Summary --------------------------------------------------------------
    elapsed_total = time.monotonic() - t_start
    logger.info(
        "Done. %d final rules | %d whitelisted | %.2fs total",
        len(optimized), wl_count, elapsed_total,
    )
    if args.dry_run:
        logger.info("[DRY-RUN] No changes were made to the system.")


if __name__ == "__main__":
    main()
