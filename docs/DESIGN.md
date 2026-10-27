# 今の仕組み（OSS を組み込んだ版）

2026-10-27 時点。Quarant 単体の版の仕組みは、元の Quarant リポジトリの [DESIGN.md](https://github.com/SaeYoshizaki/Quarant/blob/main/docs/DESIGN.md)。結果のまとめは [REPORT-2026-10.md](REPORT-2026-10.md)。

## 全体の流れ

Quarant 自身の解析はそのまま残し、同じ通信を Zeek と Suricata にも読ませる。Zeek と Suricata は分解と照合だけを受け持ち、規格の要件の証拠に変えるのは Quarant が行う。最後に結果を通信ごとに重ね、その証拠から対策のルールを作る。

```text
                              同じ PCAP
             ┌──────────────────┼──────────────────┐
             ▼                  ▼                  ▼
   ① Quarant の道         ② Zeek の道          ③ Suricata の道
   quarant analyze        quarant zeek evidence  quarant suricata evidence
             │                  │                  │
   自前で分解して判定      Zeek が分解し、        ET Open のルールで照合
   （下の「①」）          evidence.zeek が       （約 5 万件）
             │            名前と形だけを記録            │
             │            （値は残さない）              │
             │                  ▼                  ▼
             │            Quarant が規格の      Quarant が機器ごとの
             │            証拠に変換            証拠にまとめる
             │            （証明書、SSH、       （規格の要件には
             │             SNMP、版、CVE）       対応づけない）
             ▼                  ▼                  ▼
        q/events.jsonl    z/events.jsonl     suricata の証拠
             └──────────────────┼──────────────────┘
                                ▼
             ④ 重ね合わせ（quarant merge、D25）
                同じ通信・同じ種類を両方が出した → 確度を上げる
                片方だけで確度 medium 以上 → そのまま証拠
                Zeek だけで確度 low → 保留（数えない）
                                ▼
                       m/events.jsonl（最終の証拠）
                                ▼
             ⑤ 規格の要件への対応づけ（evidence-map.json）
                                ▼
             ⑥ 対策の試算（quarant countermeasure、D29）
                証拠 → 遮断・隔離のルール → 止まる通信を除いて解析し直す
```

すべての道で、次の決まりは同じ。

- すべての検出に、根拠の種類（`observed`／`inferred`／`reference_match`）、観測した事実、推定、限界、確度を付ける。どの道から来たかも付ける（`source`）。
- 値（パスワードなど）は残さない。Zeek の道は、そもそも名前と形しか記録しない。
- 時刻はパケットの時刻を使う。
- 機器には触れない（スキャン、ログインの試行、通信の改変、TLS の復号をしない）。

## ① Quarant の道（Quarant 単体の版と同じ）

```text
PCAP（ファイル or 標準入力 or ライブ）
  │  gopacket で読む（Ethernet のほか、Linux の cooked 形式も）
  ▼
パケットの分解（Ethernet / IP / TCP / UDP）
  ├─ UDP ─ DHCP・mDNS・SSDP・DNS から機器を識別。印字できる key=value の認証情報を探す
  └─ TCP ─ 接続ごとに組み立て（順番の並べ替え、再送の除去、16KB まで）
           ▼
         プロトコルの解析（自前）：HTTP、TLS（STARTTLS を含む）、MQTT、Telnet、FTP、RTSP
           ▼
         ルールで判定（約 40 個）：平文の認証情報やトークン、古い TLS、平文の画像、認証なしの操作 など
           ├─ 接続をまたぐ振る舞い（スキャン、周期通信、再接続、IP と MAC の対応の変化）
           └─ 知識ベースとの照合（カテゴリの方針、脆弱性の候補）
           ▼
出力：events.jsonl、device_inventory.json、findings.json
```

コード：`analyzer/`、`analyzer/rules/`、`analyzer/device/`、`analyzer/behavior/`。検出の条件は [DETECTION.md](DETECTION.md)。

## ② Zeek の道（D24、D27、D28）

Quarant の自前の分解では見ていなかったものを、Zeek に分解してもらう。

| Zeek から取るもの | Quarant が出す証拠 | 基準 |
|---|---|---|
| TLS の版、選ばれた暗号 | 古い TLS、壊れた暗号 | RFC 8996、IANA の暗号の一覧 |
| サーバーの証明書（鍵の種類と長さ、署名、自己署名か、期限、発行者） | 弱い証明書：RSA・DSA で 2048 ビット未満、楕円曲線で 224 ビット未満、自己署名でない SHA-1・MD5 の署名 | NIST SP 800-131A Rev.2 |
| SSH の版、鍵交換、暗号 | 弱い SSH | RFC 9142 |
| SNMP のコミュニティ名（初期値かどうかだけ）、応答の有無 | 初期のコミュニティ名を受け付けた | — |
| HTTP の認証の方式、項目の名前、Cookie の有無 | 平文の認証情報、トークン、Cookie | — |
| ソフトウェアの名前と版（Web サーバー、FTP サーバー、DHCP のクライアント、SSH） | 版の開示、脆弱性のある版の候補 | NVD、CISA KEV（手元で照合） |

- `internal/zeekevidence/evidence.zeek`：Zeek に読ませるスクリプト。値は記録しない。
- `internal/zeekevidence/zeekevidence.go`：記録を Quarant のイベントに変える。
- `internal/versionvuln/`：版を、NVD の「影響を受ける版の範囲」と照合する。キャプチャより前に公開された CVE だけを数える。照合の元は `knowledge/component_cves.json`（`scripts/knowledge/fetch_component_cves.py` で NVD API 2.0 と CISA KEV から作る）。

**確度を下げるもの**（証拠にしない。O11、O12 で決めた）

- 機器がクライアントの側で、ハンドシェイクが終わっていない接続の証明書：機器が拒んだのかもしれない。
- 版の番号が一部しかない、製品群の名前（BusyBox など）、配布版のパッケージ（Ubuntu など。版を変えずに修正を取り込む）：脆弱性のある版の候補の確度を下げる。
- 版がすべて 0 のもの：版の開示に数えない。
- 証明書の発行者名を記録し、データセットの作成者自身の中間者の試験（YourThings の `thing-catcher.gtisc.gatech.edu`）を集計から除けるようにした（[assessment/dataset-interceptors.txt](assessment/dataset-interceptors.txt)）。

## ③ Suricata の道（D26）

既知の攻撃のパターン（ET Open）との照合結果を、機器 × 種類 × ルールごとにまとめる。

| 種類 | 確度 |
|---|---|
| マルウェアの通信 | medium |
| 機器が送信元の攻撃（スキャン、DoS など） | medium |
| 機器が狙われ、応答した | medium |
| 機器が狙われたが、応答していない | low |
| 評判のリスト（悪い IP の一覧）との一致 | low |

Suricata の証拠は、**規格の要件には対応づけない**（利用者と合意）。対策（遮断、隔離）を選ぶ材料として扱う。

## ④ 重ね合わせ（D25）

`quarant merge --quarant q/ --zeek z/ [--suricata s/] --out m/`

- 同じ通信（流れのキー）で、同じ種類の証拠を両方が出したら、確度を上げ、限界に「別の解析器でも確かめた」と書き足す。
- 片方だけが出した証拠は、確度 medium 以上ならそのまま使う。
- Zeek だけが出した確度 low の証拠は、`uncorroborated.jsonl` に保留する（数えない）。

## ⑤ 規格の要件への対応づけ

[assessment/evidence-map.json](assessment/evidence-map.json) で、どの検出がどの要件（例：5.5-1 古い暗号、5.5-6 平文の秘密情報）の証拠になるかを決める。検出の種類のほか、証拠として数える条件と、除く条件を持つ。要件ごとの機器数は `scripts/assessment/integration_rates.py` で数える（[assessment/integration-rates.md](assessment/integration-rates.md)）。

## ⑥ 対策の試算（D29）

`quarant countermeasure plan | learn | filter`（`internal/countermeasure/`）

1. **plan**：規格の要件の証拠（確度 medium 以上、IoT 機器だけ）から、ゲートウェイのルールを作る。

   | 証拠が出た通信 | 作るルール |
   |---|---|
   | 外から機器へ始まった接続 | 外から機器への接続の遮断 |
   | 機器とインターネットのあいだで、平文の秘密情報・弱い暗号 | その宛先（アドレスと名前）× ポートの遮断。広いルールでは、そのポートを宛先を問わず遮断 |
   | 機器と家庭内の相手のあいだ | その機器を家庭内の他の機器から切り離す |

2. **learn**：比べる相手の「許可リスト」を作る（学習の期間に各機器が通信した宛先）。
3. **filter**：PCAP から、選んだ条件で止まるパケットを除き、Quarant と Zeek にそのまま流す。比べる条件は、普通のルーター（外から始まる接続を止める）、IoT 用のネットワーク、平文のポート（80、21、23、1883）の一律遮断、許可リスト、Quarant のルール。

- 機器は MAC で、宛先は名前で対応づける（日をまたぐとアドレスが変わるため）。名前は、キャプチャの中の DNS の答えから学ぶ（実際のゲートウェイと同じ）。
- 止めた後の機器の振る舞い（再試行、別の宛先への切り替え）は再現しない。

## 評価のための道具（検出には使わない）

| 道具 | 何に |
|---|---|
| `scripts/accuracy/`（Zeek と、標準ライブラリだけで書いた生パケットの検索） | Quarant とは別に正解を作り、見逃しを測る（E11〜E14） |
| `scripts/assessment/raw_threats.py` | Quarant にも Zeek にも頼らずに経路の危険を数える。対策の効果を独立に確かめる（O10） |
| `quarant parser-diff`（Go の標準の TLS・HTTP、mochi-mqtt） | Quarant のパーサの読み違いを見つける |

注意：見逃しの正解の一部に Zeek を使っている。Zeek を組み込んだ版（m/）の見逃しを、Zeek で作った正解で測ると、自分で自分を測ることになる。組み込んだ版の網羅性には、Zeek 以外の正解（例：YourThings の作成者による能動的な検査の結果）が要る。

## OSS をどこで使っているか

| OSS | どこで | 何に |
|---|---|---|
| gopacket | ① の本体 | パケットの読み込みと分解 |
| Zeek 9.0 | ② の分解（D24、D27、D28） | 証明書、SSH、SNMP、HTTP、ソフトウェアの版の分解 |
| Suricata 8.0（ET Open） | ③（D26） | 既知の攻撃との照合。対策の材料 |
| NVD API 2.0、CISA KEV（データ） | ② の版の照合（D28） | 脆弱性のある版の候補。手元で照合し、通信の内容は外に送らない |
| Zeek、Suricata、Snort、OpenWrt のログ | 取り込み（`quarant zeek import` など） | 外部の警告やログを取り込む（[PIPELINE.md](PIPELINE.md)） |
| Zeek 9.0、Suricata 8.0 | 評価（S2） | 同じ通信を解析して、Quarant と比べる |
| Zeek | 評価（E11〜E14） | 見逃しを測る正解の一部 |

**まだのもの**：Mercury（Cisco、通信の指紋）、nDPI（アプリの識別）。Suricata を侵入防止（IPS）として対策の比較に入れること。

## コマンド

[COMMANDS.md](COMMANDS.md)
