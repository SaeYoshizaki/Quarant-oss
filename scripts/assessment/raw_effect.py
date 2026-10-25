#!/usr/bin/env python3
"""Summarise the independent threat counts (raw_threats.py) and the
per-device collateral (filter statistics) of a countermeasure run.

For each window directory: base/raw.json (no countermeasure) and, per
condition, COND/raw.json and COND/filter2.stats.json.

Reported per condition:
  threats      (device, kind, position) triples left, and the reduction
  devices_cut  IoT devices with at least half of their packets stopped
               (their main traffic is cut off)
  median_cut   median share of packets stopped over the IoT devices
               that had traffic

usage: raw_effect.py OUT_MD NAMES_JSON WINDOW_DIR...
"""
import json
import os
import statistics
import sys

CONDS = ["router", "router+vlan", "router+ports", "router+allow", "router+quarant", "router+quarant-broad", "router+quarant-same"]
LABEL = {"router": "普通のルーター", "router+vlan": "＋IoT 用のネットワーク", "router+ports": "＋平文のポートの一律遮断",
         "router+allow": "＋許可リスト", "router+quarant": "＋Quarant（宛先ごと）", "router+quarant-broad": "＋Quarant（広いルール）",
         "router+quarant-same": "＋Quarant（同じ期間の計画）"}


def threats(path):
    if not os.path.exists(path):
        return None
    return {(t["device"], t["kind"], t["position"]) for t in json.load(open(path))["threats"]}


def collateral(path):
    if not os.path.exists(path):
        return None, None
    per = json.load(open(path))["stats"].get("per_device") or {}
    shares = [c["stopped"] / c["packets"] for c in per.values() if c["packets"] > 0]
    if not shares:
        return 0, 0.0
    return sum(1 for s in shares if s >= 0.5), statistics.median(shares)


def main():
    out, names_path = sys.argv[1:3]
    windows = sys.argv[3:]
    L = ["# 独立した物差しでの脅威の残りと、機器ごとの止めすぎ", "",
         "`scripts/assessment/raw_effect.py` で生成。脅威は `raw_threats.py`（Quarant にも Zeek にも頼らない生のパケットの検索）で数えた「機器 × 種類 × 位置」。",
         "主な通信が止まった機器：パケットの半分以上が止まった IoT 機器の数。中央値：IoT 機器ごとの止めたパケットの割合の中央値。", ""]
    head = "| 条件 | " + " | ".join(os.path.basename(w.rstrip('/')) for w in windows) + " |"
    L += ["## 脅威の残り（減り方）", "", head, "|---|" + "---|" * len(windows)]
    base = {w: threats(os.path.join(w, "base", "raw.json")) or set() for w in windows}
    L.append("| 対策なし | " + " | ".join(str(len(base[w])) for w in windows) + " |")
    for c in CONDS:
        cells = []
        for w in windows:
            t = threats(os.path.join(w, c, "raw.json"))
            if t is None:
                cells.append("—")
            else:
                b = len(base[w])
                cells.append(f"{len(t)}（{100 * (b - len(t)) / b:.0f}% 減）" if b else str(len(t)))
        L.append(f"| {LABEL[c]} | " + " | ".join(cells) + " |")
    L += ["", "## 機器ごとの止めすぎ（主な通信が止まった機器 / 止めた割合の中央値）", "", head, "|---|" + "---|" * len(windows)]
    for c in CONDS:
        cells = []
        for w in windows:
            n, med = collateral(os.path.join(w, c, "filter2.stats.json"))
            cells.append("—" if n is None else f"{n} 台 / {100 * med:.1f}%")
        L.append(f"| {LABEL[c]} | " + " | ".join(cells) + " |")
    open(out, "w").write("\n".join(L) + "\n")
    print("\n".join(L))


if __name__ == "__main__":
    main()
