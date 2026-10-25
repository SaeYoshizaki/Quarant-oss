#!/usr/bin/env python3
"""Detection side of the OSS integration: for each provision in
evidence-map.json, how many devices have evidence from Quarant alone (q/)
and from Quarant overlaid with the Zeek path (m/), per dataset group.

Credentials sent to a device by a host that scanned the devices as part of
the dataset (SCANNERS, e.g. the Nessus host of YourThings 2018-03-20) are
not counted for the credential provisions: they are guesses, not the
device's password (as for the attackers' guesses in E9). Credentials a
household phone sends to a device still count: the device accepts a
cleartext login.

Each run directory holds q/, z/ and m/ as written by rerun-oss1.sh. Devices
are counted by MAC within a group, as in evidence_rates.py; the observed
devices come from Quarant's device_inventory.json. Only medium and high
confidence events count (low ones are not evidence on their own, D25).

usage: integration_rates.py EVIDENCE_MAP EXCLUDE_MACS SCANNERS OUT_MD RUN_ROOT...
"""
import collections
import glob
import json
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
import evidence_rates as er  # noqa: E402

CREDENTIAL = {"5.1-1", "5.1-2", "5.1-2A", "5.5-6", "5.5-7"}
GROUPS = dict(er.GROUPS)
GROUPS["iot-"] = "UNSW-IoTraffic 2016-17"
GROUPS["deakin-2023"] = "Deakin 2023"
GROUPS["deakin-2024"] = "Deakin 2024"


def inventory(d):
    p = os.path.join(d, "device_inventory.json")
    inv = {}
    if os.path.exists(p):
        for dev in json.load(open(p)).get("devices") or []:
            inv[dev["ip"]] = dev
    return inv


def main():
    emap, excl, scan, out_md = sys.argv[1:5]
    roots = sys.argv[5:]
    scanners = {l.strip().lower() for l in open(scan) if l.strip() and not l.startswith("#")}
    provs = [p for p in json.load(open(emap))["provisions"]
             if p["signals"] and not p["signals"][0].startswith("identity_evidence")]
    exclude = {l.strip().lower() for f in excl.split(",") for l in open(f) if l.strip() and not l.startswith("#")}
    seen = collections.defaultdict(set)
    hit = {s: collections.defaultdict(lambda: collections.defaultdict(set)) for s in ("q", "m")}
    for root in roots:
        for d in sorted(glob.glob(os.path.join(root, "*"))):
            name = os.path.basename(d)
            group = next((g for p, g in GROUPS.items() if name.startswith(p)), None)
            if group is None or not os.path.exists(os.path.join(d, "m", "events.jsonl")):
                continue
            inv = inventory(os.path.join(d, "q"))
            keys = set()
            for side in ("q", "m"):
                with open(os.path.join(d, side, "events.jsonl")) as f:
                    for line in f:
                        e = json.loads(line)
                        if e.get("debug"):
                            continue
                        keys.add(e.get("device_key"))
                        if e.get("confidence") == "low":
                            continue
                        mac = er.device_id(inv, e.get("device_key") or e.get("src_ip", ""))
                        if mac in exclude:
                            continue
                        dev = e.get("device_key") or ""
                        to_device = dev and dev == e.get("dst_ip")
                        peer_mac = er.device_id(inv, e.get("src_ip", "")) if to_device else ""
                        for p in provs:
                            if not er.matches(p, e):
                                continue
                            if p["provision"] in CREDENTIAL and to_device and peer_mac in scanners:
                                continue
                            hit[side][group][p["provision"]].add(mac)
            for ip, dev in inv.items():
                mac = er.device_id(inv, ip)
                if (dev.get("observed_protocols") or ip in keys) and mac not in exclude:
                    seen[group].add(mac)
    groups = [g for g in GROUPS.values() if g in seen]
    L = ["# Quarant 単体と OSS を組み込んだ版：要件ごとの機器数", "",
         "`scripts/assessment/integration_rates.py` で生成。各セルは「Quarant 単体 → OSS 組み込み」（機器数、MAC で数える）。確度 low の証拠は数えない。", "",
         "| 要件 | " + " | ".join(groups) + " |", "|---|" + "---|" * len(groups),
         "| （通信が観測された機器） | " + " | ".join(str(len(seen[g])) for g in groups) + " |"]
    for p in provs:
        v = p["provision"]
        cells = []
        for g in groups:
            q, m = len(hit["q"][g][v] & seen[g]), len(hit["m"][g][v] & seen[g])
            cells.append("—" if q == m == 0 else (f"{q}" if q == m else f"{q} → **{m}**"))
        L.append(f"| {v} | " + " | ".join(cells) + " |")
    open(out_md, "w").write("\n".join(L) + "\n")
    print("\n".join(L))


if __name__ == "__main__":
    main()
