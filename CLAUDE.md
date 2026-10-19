# CLAUDE.md

Quarant：家庭内 IoT 機器の通信を**パッシブに**監視し、何が分かり何が分からないかを根拠つきで示す研究用システム（Go）。

**このリポジトリ（Quarant-oss）は、OSS（Zeek、Suricata）を組み込む版（論文 2）**。Quarant 単体の版は元の Quarant リポジトリにあり、比べる相手として残している。単体の解析（`quarant analyze`）を変える変更は、ここだけで行い、元のリポジトリには入れない。

## 最初に読むもの

- [docs/STATUS.md](docs/STATUS.md)：現状、既知の問題、次の作業
- [docs/RESEARCH.md](docs/RESEARCH.md)：研究の問い（ETSI EN 303 645 × 厳密にパッシブな可観測性）、関連研究、評価計画。1 ページの要約は [docs/RESEARCH-SUMMARY.md](docs/RESEARCH-SUMMARY.md)
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)：設計原則と構成
- [docs/ROADMAP.md](docs/ROADMAP.md)：研究として進める順序（Step 0〜5）
- [docs/DECISIONS.md](docs/DECISIONS.md)：設計判断の記録（判断を変えたら追記する）
- [docs/DETECTION.md](docs/DETECTION.md)、[docs/EVALUATION.md](docs/EVALUATION.md)、[docs/TESTING.md](docs/TESTING.md)、[docs/EXPERIMENTS.md](docs/EXPERIMENTS.md)、[docs/DATASETS.md](docs/DATASETS.md)

## 恒久ルール

- **パッシブ監視**：監視対象の機器への能動的な操作（スキャン、認証試行、ペイロードの送信、通信の改変、TLS の復号）を実装しない。能動的な検査は、利用者の明示的な許可が必要な別機能として提案する。
- **イベントの必須項目**：すべてのイベントに `basis`（`observed`／`inferred`／`reference_match`、`analyzer/basis.go`）と、`observed_fact`、`inference`、`limitation`、`confidence` を付ける。
- **断定しない**：「疑い」と「確定」、「関連する CVE がある」と「脆弱である」を区別する。未検出を安全の証明として扱わない。
- **数値スコア**：根拠のない数値スコアを新たに作らない。
- **時刻**：解析ではキャプチャ時刻を使う（`time.Now()` を解析ロジックに入れない）。
- **秘密情報**：認証情報や生のペイロードを、イベントやログに書かない（`***` でマスクする）。PCAP や秘密情報を git に入れない。外部への送信は最小限にし、脅威情報はローカルで照合する。
- **既存コードの尊重**：全面的な書き直しをしない。既存の機能を消すとき、大規模な設計変更、有料サービスの利用、外部へのデータ送信、実機への操作、push、大量の削除は、事前に利用者に確認する。
- **完了の条件**：変更したら `gofmt`、`go vet ./...`、`go test ./...` を通す。検出ロジックを変えたら、`analyzer/scenario_test.go` と `quarant label-eval` で回帰を確認する。
- **報告**：利用者への説明は日本語で行う。完了報告では、実装済み・テスト済み・未検証を区別する。

## よく使うコマンド

```bash
go test ./...
go run ./cmd/quarant analyze examples/pcap/synthetic-home.pcap --out runs/demo/events.jsonl
go run ./cmd/quarant devices --in runs/demo
go run ./cmd/quarant label-eval --events runs/demo/events.jsonl --labels examples/pcap/synthetic-home.labels.json
```
