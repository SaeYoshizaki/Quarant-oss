#!/usr/bin/env python3
"""Second paper: how much evidence remains after simulated countermeasures
(quarant countermeasure plan/filter). For each provision in evidence-map.json
the script counts the devices with evidence before and after each
countermeasure, the same way evidence_rates.py counts devices.

Only medium and high confidence events count (low ones are not evidence on
their own, D25). Devices are identified by MAC; addresses are mapped to
MACs with the run's device_inventory.json or, for a Zeek-only run, the
MACs in quarant_evidence.log (--ipmac).

usage: countermeasure_effect.py EVIDENCE_MAP EXCLUDE_MACS OUT_MD BEFORE_DIR NAME=AFTER_DIR... [--ipmac LOG] [--names JSON]
"""
import argparse
import collections
import json
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
import evidence_rates as er  # noqa: E402


def ipmac_from_inventory(d):
    p = os.path.join(d, "device_inventory.json")
    out = {}
    if os.path.exists(p):
        for dev in json.load(open(p)).get("devices") or []:
            if dev.get("mac_address"):
                out[dev["ip"]] = dev["mac_address"].lower()
    return out


def ipmac_from_log(path):
    out = {}
    for line in open(path):
        r = json.loads(line)
        for h, m in ((r.get("orig_h"), r.get("orig_mac")), (r.get("resp_h"), r.get("resp_mac"))):
            if h and m:
                out.setdefault(h, m.lower())
    return out


def hits(d, provs, ipmac, exclude):
    out = collections.defaultdict(set)
    with open(os.path.join(d, "events.jsonl")) as f:
        for line in f:
            e = json.loads(line)
            if e.get("debug") or e.get("confidence") == "low":
                continue
            mac = ipmac.get(e.get("device_key") or "", e.get("device_key") or "")
            if mac in exclude:
                continue
            for p in provs:
                if er.matches(p, e):
                    out[p["provision"]].add(mac)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("emap")
    ap.add_argument("exclude")
    ap.add_argument("out_md")
    ap.add_argument("before")
    ap.add_argument("after", nargs="+")
    ap.add_argument("--ipmac")
    ap.add_argument("--names")
    a = ap.parse_args()
    provs = [p for p in json.load(open(a.emap))["provisions"]
             if p["signals"] and not p["signals"][0].startswith("identity_evidence")]
    exclude = {l.strip().lower() for l in open(a.exclude) if l.strip() and not l.startswith("#")}
    ipmac = ipmac_from_log(a.ipmac) if a.ipmac else ipmac_from_inventory(a.before)
    names = json.load(open(a.names)) if a.names else {}
    before = hits(a.before, provs, ipmac, exclude)
    afters = []
    for spec in a.after:
        name, d = spec.split("=", 1)
        afters.append((name, hits(d, provs, ipmac, exclude)))
    L = ["# 対策の前後で証拠が残る機器の数", "",
         "`scripts/assessment/countermeasure_effect.py` で生成。値は「証拠が残る機器の数」。確度 low の証拠は数えない。", "",
         "| 要件 | 対策なし | " + " | ".join(n for n, _ in afters) + " |", "|---|---|" + "---|" * len(afters)]
    detail = {}
    for p in provs:
        v = p["provision"]
        if not before[v] and not any(h[v] for _, h in afters):
            continue
        L.append(f"| {v} | {len(before[v])} | " + " | ".join(f"{len(h[v])}" for _, h in afters) + " |")
        detail[v] = {n: sorted(names.get(m, m) for m in h[v]) for n, h in afters}
        detail[v]["before"] = sorted(names.get(m, m) for m in before[v])
    allb = set().union(*before.values()) if before else set()
    L.append(f"| （いずれかの要件） | {len(allb)} | " + " | ".join(str(len(set().union(*h.values()) if h else set())) for _, h in afters) + " |")
    open(a.out_md, "w").write("\n".join(L) + "\n")
    json.dump(detail, open(os.path.splitext(a.out_md)[0] + ".json", "w"), ensure_ascii=False, indent=1)
    print("\n".join(L))


if __name__ == "__main__":
    main()
