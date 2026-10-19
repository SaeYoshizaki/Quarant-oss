# コマンド

PCAP と解析の出力（`runs/`）は git に入れない。リポジトリにある PCAP は合成したものだけ。

## 基本

```bash
go test ./...

# 合成 PCAP（正解ラベル付き）で動かす
go run ./cmd/quarant analyze examples/pcap/synthetic-home.pcap --out runs/demo/events.jsonl
go run ./cmd/quarant devices --in runs/demo          # 機器ごとのレポート（見えなかったことも出す）
go run ./cmd/quarant findings --in runs/demo         # 機器 × 状態の要約（findings.json）
go run ./cmd/quarant label-eval --events runs/demo/events.jsonl --labels examples/pcap/synthetic-home.labels.json

# 自分のネットワークの PCAP（監視範囲を指定）
go run ./cmd/quarant analyze capture.pcap --local-net 192.168.1.0/24 --out runs/home/events.jsonl

# 日ごとの PCAP を続けて解析するとき、機器の名乗りを引き継ぐ（D22）
go run ./cmd/quarant analyze day2.pcap --identity-state runs/home/identity-state.json --out runs/day2/events.jsonl

# 標準入力から読む（分割された PCAP をつなげて流すとき）
python3 scripts/accuracy/pcapcat.py part1.pcap part2.pcap | go run ./cmd/quarant analyze - --out runs/day/events.jsonl

# ライブキャプチャ（動作確認は未実施）
go run ./cmd/quarant live --iface en0 --out runs/live/events.jsonl
```

## 評価

```bash
# 公開データセットでの評価、パーサの差分検査
go run ./cmd/quarant dataset-eval iot23|unsw|unsw-attacks ...
go run ./cmd/quarant parser-diff --pcap capture.pcap

# 要件ごとの出現率（E4、E15）。厳しい読み方の対応表は readings.py で作る
python3 scripts/assessment/readings.py docs/assessment/evidence-map.json docs/assessment/evidence-map-strict.json
python3 scripts/assessment/evidence_rates.py docs/assessment/evidence-map.json <runs>[,<runs>...] out.md samples.json docs/assessment/non-iot-macs.txt

# 見逃しの測定（E11〜E14）：Quarant と独立した正解（Zeek と生パケットの検索）を作って比べる
scripts/accuracy/run_gt.sh <gt-out> 6
scripts/accuracy/run_split_day.sh <quarant-bin> <day-dir> <name> <runs-out> <gt-out>   # 5 分ごとに分かれた PCAP（YourThings）
python3 scripts/accuracy/compare_misses.py docs/assessment/evidence-map.json <runs> <gt> <non-iot-macs> out.json docs/assessment/miss-judgments.json
python3 scripts/accuracy/check_application.py <runs> <gt> <non-iot-macs> out.json
```

S2（Zeek、Suricata との比較）は [scripts/step2/README.md](../scripts/step2/README.md)。

## 外部ログのパイプライン

説明は [PIPELINE.md](PIPELINE.md)。

### 外部ログのパイプライン：Taxonomy normalization

```bash
go run ./cmd/quarant taxonomy policy \
  --out taxonomy_policy.json
```

```bash
go run ./cmd/quarant taxonomy coverage \
  --security-events runs/experiment-001/before/assembled/security_events.jsonl \
  --policy taxonomy_policy.json \
  --out taxonomy_coverage_report.json
```

### 外部ログのパイプライン：最小 demo

```bash
go run ./cmd/quarant openwrt import \
  --dhcp-leases examples/openwrt/before/raw/dhcp.leases \
  --dns-log examples/openwrt/before/raw/dnsmasq.log \
  --firewall-log examples/openwrt/before/raw/firewall.log \
  --conntrack examples/openwrt/before/raw/conntrack.txt \
  --out-dir runs/openwrt-demo/before
```

```bash
go run ./cmd/quarant experiment run \
  --before-openwrt examples/integrated/before/openwrt/raw \
  --before-suricata examples/integrated/before/suricata/raw/eve.json \
  --before-zeek examples/integrated/before/zeek/raw \
  --before-snort examples/integrated/before/snort/raw/alert.fast \
  --after-openwrt examples/integrated/after/openwrt/raw \
  --after-suricata examples/integrated/after/suricata/raw/eve.json \
  --after-zeek examples/integrated/after/zeek/raw \
  --after-snort examples/integrated/after/snort/raw/alert.fast \
  --before-now 2026-09-26T12:30:00Z \
  --after-now 2026-09-26T13:30:00Z \
  --out runs/experiment-001
```

### 外部ログのパイプライン：Docker OpenWrt-compatible lab

```bash
cd evaluation/docker-openwrt-lab
docker compose up --abort-on-container-exit
```

```bash
go run ./cmd/quarant experiment run \
  --before-openwrt evaluation/docker-openwrt-lab/out/before/openwrt/raw \
  --after-openwrt evaluation/docker-openwrt-lab/out/after/openwrt/raw \
  --before-now 2026-09-26T12:30:00Z \
  --after-now 2026-09-26T13:30:00Z \
  --out runs/docker-openwrt-lab
```

### 外部ログのパイプライン：OpenWrt commands

```bash
go run ./cmd/quarant openwrt setup-plan \
  --iot-port lan4 \
  --out openwrt-quarant-setup.sh
```

```bash
go run ./cmd/quarant openwrt import \
  --dhcp-leases raw/dhcp.leases \
  --dns-log raw/dnsmasq.log \
  --firewall-log raw/firewall.log \
  --conntrack raw/conntrack.txt \
  --out-dir runs/openwrt-001
```

```bash
go run ./cmd/quarant openwrt collect \
  --host root@192.168.50.1 \
  --out-dir runs/openwrt-001
```

### 外部ログのパイプライン：Suricata / Zeek / Snort commands

```bash
go run ./cmd/quarant suricata import \
  --eve raw/eve.json \
  --out-dir runs/suricata-001
```

```bash
go run ./cmd/quarant zeek import \
  --conn raw/conn.log \
  --dns raw/dns.log \
  --http raw/http.log \
  --ssl raw/ssl.log \
  --out-dir runs/zeek-001
```

Zeek に PCAP を読ませて、規格の要件の証拠を作る（D24）。出力は `events.jsonl`（`analyze` と同じ形、`source: zeek`）と `quarant_evidence.log`（名前と形だけ）。`--log` で既存の `quarant_evidence.log` や `gt.log` も読める。

```bash
go run ./cmd/quarant zeek evidence --pcap capture.pcap --out runs/zeek-evidence-001
```

Suricata の警告を、機器ごとの証拠にする（D26）。

```bash
go run ./cmd/quarant suricata evidence --eve eve.json --out runs/suricata-evidence-001
```

`analyze` の結果と通信ごとに重ねる（D25、D26）。`quarant merge --quarant DIR [--zeek DIR] [--suricata DIR] --out DIR`。`zeek merge` は Zeek だけの形。出力は `events.jsonl`（各イベントに `sources`）、`uncorroborated.jsonl`（Zeek・Suricata の確度 low で、Quarant が出していないもの）、`merge_summary.json`、`device_inventory.json`。

```bash
go run ./cmd/quarant merge --quarant runs/demo --zeek runs/zeek-evidence-001 \
  --suricata runs/suricata-evidence-001 --out runs/merged-001
```

Quarant 単体との比較（O1）：

```bash
python3 scripts/assessment/compare_sources.py docs/assessment/evidence-map.json \
  RUNS_QUARANT RUNS_ZEEK EXCLUDE_MACS out.md out.json
```

```bash
go run ./cmd/quarant snort import \
  --alerts raw/alert.fast \
  --rules raw/local.rules \
  --out-dir runs/snort-001
```

### 外部ログのパイプライン：Evidence assemble

```bash
go run ./cmd/quarant evidence assemble \
  --openwrt runs/openwrt-001 \
  --suricata runs/suricata-001 \
  --zeek runs/zeek-001 \
  --snort runs/snort-001 \
  --out runs/assembled-001
```

### 外部ログのパイプライン：Experiment batch

```bash
go run ./cmd/quarant experiment batch \
  --config examples/integrated/experiments.yaml \
  --out runs/batch-001
```

### 外部ログのパイプライン：Quality gate

```bash
go run ./cmd/quarant quality-gate \
  --experiment runs/experiment-001 \
  --taxonomy-coverage runs/experiment-001/before/assembled/taxonomy_coverage_report.json \
  --out runs/experiment-001/quality_gate_report.json \
  --research-out runs/experiment-001/guarded_research_report.json
```

### 外部ログのパイプライン：Research report

```bash
go run ./cmd/quarant research-report \
  --precision precision_report.json \
  --precision-eval precision_eval_report.json \
  --mitigation mitigation_plan.json \
  --mitigation-eval mitigation_eval_report.json \
  --source-coverage source_coverage_report.json \
  --taxonomy-coverage taxonomy_coverage_report.json \
  --out research_report.json
```
