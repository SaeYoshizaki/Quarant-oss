# 今の仕組み

2026-10-19 時点。これから作る構成は [ARCHITECTURE.md](ARCHITECTURE.md)。

## 全体の流れ

```text
PCAP（ファイル or 標準入力 or ライブ）
  │  gopacket で読む
  ▼
パケットの分解（Ethernet / IP / TCP / UDP）
  │
  ├─ UDP ─ DHCP・mDNS・SSDP・DNS から機器を識別
  │        印字できる key=value の認証情報を探す
  │
  └─ TCP ─ 接続ごとに組み立て（順番の並べ替え、再送の除去、16KB まで）
           │
           ▼
         プロトコルの解析（自前）
           HTTP（既定のポート ＋ 中身で判断）、TLS（中身で判断、STARTTLS を含む）、
           MQTT、Telnet、FTP、RTSP
           │
           ▼
         ルールで判定（約 40 個、analyzer/rules）
           平文の認証情報やトークン、古い TLS、平文の画像、認証なしの操作 など
           │
           ├─ 接続をまたぐ振る舞い（スキャン、周期通信、再接続、IP と MAC の対応の変化）
           └─ 知識ベースとの照合（カテゴリの方針、脆弱性の候補）
           │
           ▼
出力：events.jsonl（検出）、device_inventory.json（機器）、findings.json（機器 × 状態の要約）
```

- すべての検出に、根拠の種類（`observed`／`inferred`／`reference_match`）、観測した事実、推定、限界を付ける。
- 値（パスワードなど）は `***` に伏せて出す。
- 時刻はパケットの時刻を使う。
- コード：`analyzer/`（流れと組み立て）、`analyzer/rules/`（プロトコルの解析とルール）、`analyzer/device/`（機器の識別）、`analyzer/behavior/`（振る舞い）。検出の条件は [DETECTION.md](DETECTION.md)。

## OSS をどこで使っているか

| OSS | どこで | 何に |
|---|---|---|
| gopacket | 解析の本体 | パケットの読み込みと分解 |
| Zeek 9.0 | 試作（`quarant zeek evidence`、`zeek merge`、D24、D25） | Zeek の分解から規格の要件の証拠を作り、Quarant の結果と通信ごとに重ねる（O1、O2） |
| Zeek、Suricata、Snort、OpenWrt のログ | 取り込み（`quarant zeek import` など） | 外部の警告やログを取り込み、インシデントの整理と対策の前後比較に使う（[PIPELINE.md](PIPELINE.md)） |
| Zeek 9.0、Suricata 8.0（ET Open） | 評価（S2） | 同じ通信を解析して、Quarant と比べる |
| Zeek | 評価（E11〜E14） | Quarant とは別に正解を作り、見逃しを測る |
| Go の標準の TLS・HTTP、mochi-mqtt | 評価（`quarant parser-diff`） | Quarant のパーサの読み違いを見つける |

**組み込んでいないもの**：規格の要件の証拠（RESULTS.md の 2）は、Quarant 自身の解析だけで出している。Zeek 経由の証拠（D24）と、`analyze` の結果との重ね合わせ（D25）は試作。Suricata の結果は、検出には使っていない。

## コマンド

[COMMANDS.md](COMMANDS.md)
