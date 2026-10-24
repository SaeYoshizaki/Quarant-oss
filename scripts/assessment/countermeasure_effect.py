#!/usr/bin/env python3
"""Second paper: how much evidence remains after simulated countermeasures
(quarant countermeasure plan/filter). For each provision in evidence-map.json
the script counts the devices with evidence before and after each
countermeasure, the same way evidence_rates.py counts devices.

Only medium and high confidence events count (low ones are not evidence on
their own, D25). Devices are identified by MAC; addresses are mapped to
MACs with the run's device_inventory.json or, for a Zeek-only run, the
MACs in quarant_evidence.log (--ipmac).

A threat is a (device, provision, attacker position) triple. Positions:
internet_path (the evidence is on traffic between the device and the
internet: an observer on the path), inbound (an internet host connected to
the device) and home (both ends inside the home network). Provisions are
read as path risks or device properties (D29); 5.3-4A is evidence of
conformance and is not counted as a threat.

An AFTER spec may name the filter's stats file, NAME=DIR@STATS.json, to
report how much the countermeasure stopped (packets, destinations).

usage: countermeasure_effect.py EVIDENCE_MAP EXCLUDE_MACS OUT_MD BEFORE_DIR NAME=AFTER_DIR[@STATS]... [--ipmac LOG] [--names JSON]
"""
import argparse
import collections
import ipaddress
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


PATH = {"5.1-2A", "5.1-3", "5.5-1", "5.5-6", "5.5-7", "5.8-1", "5.8-2", "5.3-7", "6-8"}
NOT_THREAT = {"5.3-4A"}


def kind(prov):
    return "path" if prov in PATH else "property"


def is_local(ip):
    try:
        a = ipaddress.ip_address(ip)
        return a.is_private or a.is_link_local
    except ValueError:
        return False


def position(e):
    dev, src, dst = e.get("device_key") or "", e.get("src_ip") or "", e.get("dst_ip") or ""
    peer = dst if dev != dst else src
    if not peer or is_local(peer):
        return "home" if peer else "device"
    return "inbound" if dev == dst else "internet_path"


def hits(d, provs, ipmac, exclude):
    """provision -> devices, and the set of (device, provision, position)."""
    out = collections.defaultdict(set)
    threats = set()
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
                    if p["provision"] not in NOT_THREAT:
                        threats.add((mac, p["provision"], position(e)))
    return out, threats


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
    before, bthreats = hits(a.before, provs, ipmac, exclude)
    afters, athreats, stats = [], {}, {}
    for spec in a.after:
        name, d = spec.split("=", 1)
        d, _, st = d.partition("@")
        h, t = hits(d, provs, ipmac, exclude)
        afters.append((name, h))
        athreats[name] = t
        if st and os.path.exists(st):
            stats[name] = json.load(open(st)).get("stats", {})
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

    # Threats: (device, provision, position), with how much each condition stopped.
    def count(ts, k=None, pos=None):
        return sum(1 for (_, prov, ps) in ts if (k is None or kind(prov) == k) and (pos is None or ps == pos))

    def pct(after, before):
        return f"{after} ({100 * (before - after) / before:.0f}% 減)" if before else f"{after}"
    L += ["", "## 脅威（機器 × 要件 × 攻撃者の位置）の残り", "",
          "経路：通信の経路で起きる危険（消えれば危険がなくなる）。性質：機器の中身の問題（届く範囲が狭まるだけ）。位置：internet_path＝インターネットとの通信の経路、inbound＝外から機器への接続、home＝家庭内。",
          "", "| 条件 | すべて | 経路 | 性質 | internet_path | inbound | home | 止めたパケット | 止めた宛先 |",
          "|---|---|---|---|---|---|---|---|---|"]
    rows = [("対策なし", bthreats, None)] + [(n, athreats[n], stats.get(n)) for n, _ in afters]
    for name, ts, st in rows:
        cells = [pct(count(ts), count(bthreats)), pct(count(ts, "path"), count(bthreats, "path")),
                 pct(count(ts, "property"), count(bthreats, "property"))]
        cells += [pct(count(ts, pos=ps), count(bthreats, pos=ps)) for ps in ("internet_path", "inbound", "home")]
        if st:
            cells += [f"{100 * st.get('dropped', 0) / max(1, st.get('packets', 1)):.1f}%", str(st.get("blocked_destinations", ""))]
        else:
            cells += ["—", "—"]
        L.append(f"| {name} | " + " | ".join(cells) + " |")
    open(a.out_md, "w").write("\n".join(L) + "\n")
    json.dump(detail, open(os.path.splitext(a.out_md)[0] + ".json", "w"), ensure_ascii=False, indent=1)
    print("\n".join(L))


if __name__ == "__main__":
    main()
