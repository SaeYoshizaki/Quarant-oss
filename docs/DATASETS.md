# 評価用公開データセットの選定

調査日：2026-10-17。この時点ではデータはダウンロードしていない。

**表記**

- ✔：一次情報（公式ページ、ライセンス本文）で確認済み
- （未確認）：論文や二次情報によるもので、まだ確かめていない

## 選定条件（Quarant の要件）

1. **生の PCAP**であること。特徴量 CSV だけのデータセットは使えない。
2. **LAN 側のキャプチャ**であること。Ethernet ヘッダ、DHCP、mDNS、SSDP が見えないと機器識別を検証できない。
3. **正解ラベル**があること。機器（MAC から機器への対応）、または攻撃（時間窓かフロー単位）。
4. **研究で使える条件**であること。ライセンスが明確で、引用条件を満たせる。必要なら再配布も可能。

## 推奨する組み合わせ

| 用途 | データセット | 理由 |
|---|---|---|
| 機器識別と正常時のベースライン（主） | **UNSW IoT Traffic Traces** | MIT-0 ✔。PCAP ✔。MAC と機器の対応表 31 件 ✔。OpenWrt ゲートウェイの LAN 側で取得（論文による。未確認）。DHCP、mDNS、SSDP、識別、誤検知（正常な機器）を検証できる |
| ARP スプーフィングと、同じ環境での攻撃（補助） | **UNSW IoT Attack Traces** | MIT-0 ✔。PCAP ✔。攻撃の開始・終了時刻、種類の注釈 ✔（例：`ArpSpoof100L2D`、2018 年 6 月）。ベースラインと同じテストベッドなので比較しやすい |
| マルウェアの振る舞い（主） | **IoT-23**（Stratosphere） | CC BY 4.0 ✔（Zenodo）。PCAP と、ラベル付きの Zeek conn.log ✔。ラベルに `PartOfAHorizontalPortScan`、`C&C-HeartBeat`、`Mirai` などがある ✔。実際のマルウェア（Mirai など）を動かしたキャプチャ |
| 新しい機器の識別と TLS（補助） | **CIC IoT Dataset 2022** | 引用すれば再配布可 ✔。登録フォームが必要。2022 年の機器なので、古いデータセットだけで生じる TLS 評価の偏りを補える |

この組み合わせにより、研究の問い「パッシブ監視で何が分かり、何が分からないか」を、次の 3 つの軸で測れる。

- 機器識別（UNSW traces、CIC 2022）
- 平文と TLS（全データセット）
- 攻撃と振る舞い（IoT-23、UNSW attacks）

あわせて、ファームウェアの年代の違い（2016、2018–19、2022）も比較できる。

## 各データセットで検証できることと限界

### UNSW IoT Traffic Traces

- **引用**：Sivanathan et al., "Classifying IoT Devices in Smart Environments Using Network Traffic Characteristics", IEEE TMC
- **URL**：https://iotanalytics.unsw.edu.au/iottraces.html
- **ライセンス**：MIT-0 ✔
- **形式**：日ごとの PCAP と CSV。シェルスクリプトで一括ダウンロードできる ✔。キャプチャ日（2016 年ごろ）と容量は未確認。
- **正解**：`List_Of_Devices.txt`（機器名、MAC、有線／無線）✔。攻撃のラベルはなく、全体を正常として扱う。
- **検証できること**：
  - OUI ベンダー、DHCP ホスト名、option 55、mDNS、SSDP の識別率（正解 MAC との一致）
  - 正常な機器での誤検知（特に `PERIODIC_*`、TLS、I3〜I6）
  - クラウドへの死活監視通信を周期通信として検出できるか
- **限界**：2016 年前後のファームウェアなので、TLS の評価は現在の機器より悪く出る。攻撃は含まれない。

### UNSW IoT Benign and Attack Traces

- **引用**：Hamza et al., "Detecting Volumetric Attacks on IoT Devices via SDN-Based Monitoring of MUD Activity", ACM SOSR 2019
- **URL**：https://iotanalytics.unsw.edu.au/attack-data.html
- **ライセンス**：MIT-0 ✔
- **形式**：PCAP、フローカウンタ、注釈 ✔。注釈は「開始と終了の Unix 時刻、影響を受けたフロー、攻撃の種類」✔。
- **攻撃**：ARP スプーフィング ✔、SYN flood、各種リフレクション（後者は未確認）。
- **検証できること**：`IP_MAC_BINDING_CHANGED`（ARP スプーフィング）の再現率。フラッド攻撃は、Quarant に現在検出器がないことを確認する用途（Phase 2 の候補）。
- **限界**：
  - 攻撃はラボのツールで生成したもので、量で押すタイプが中心。
  - Mirai、外向きのスキャン、C2 は含まれない。

### IoT-23

- **引用**：Garcia, Parmisano, Erquiaga (2020), IoT-23, Zenodo, doi:10.5281/zenodo.4743746
- **URL**：https://www.stratosphereips.org/datasets-iot23
- **ライセンス**：CC BY 4.0 ✔
- **形式**：全体アーカイブ 21.5GB（PCAP を含む）✔。PCAP を除いた版は 8.8GB ✔。
- **シナリオ**：悪性 20 件と正常 3 件 ✔。正常の 3 件は Philips Hue、Amazon Echo、Somfy のドアロック ✔。
- **正解**：Zeek の flow 単位のラベル ✔。
- **検証できること**：
  - `OUTBOUND_SCAN_SUSPECTED`（Mirai の 23/2323 番ポートへのスキャン）
  - `PERIODIC_COMMUNICATION_OBSERVED`（`C&C-HeartBeat`）
  - 正常な 3 機器での誤検知
- **限界**：
  - 感染させた機器は主に Raspberry Pi で、市販の IoT 機器ではない（論文と二次情報による。未確認）。
  - 1 シナリオに 1 台なので、LAN の文脈（他の機器の mDNS など）はほぼない。機器識別の検証には使えない。
  - ラベルは flow 単位なので、5-tuple と時刻で Quarant のイベントと結合する必要がある。

### CIC IoT Dataset 2022

- **引用**：Dadkhah et al., PST 2022
- **URL**：https://www.unb.ca/cic/datasets/iotdataset-2022.html
- **ライセンス**：CIC 共通の条件 ✔ ── "You may redistribute, republish, and mirror our datasets in any form; however, any use or redistribution of the data must include a citation to the dataset and the research paper listed."
- **形式**：PCAP。種類別のアーカイブに分かれている。登録フォームが必要。
  - 1-Power（起動時）、2-Idle（待機時）、3-Interactions（操作時）、4-Scenarios、5-Active、6-Attacks
  - CSV（特徴量）、Z-Wave と Zigbee の実験
  - 1-Power は確認済み（2026-10-17）。機器ごと、試行ごとに 1 つの PCAP（40 台 × 3 回 = 120 個）で、中身は機器とゲートウェイだけ。ゲートウェイは 192.168.137.1（Windows のインターネット共有、MAC 3c:18:a0:45:da:85）。
  - 保存先は USB ドライブ（`/Volumes/Untitled/CIC_IOT_Dataset2022`。展開先は `quarant-datasets/cic-iot-2022/`）。解析は `~/datasets/scripts/run-cic.sh <part>`。
- **検証できること**：新しい機器での識別（起動時の DHCP）、TLS の実態、RTSP のブルートフォース。
- **限界**：攻撃は少ない。ハブを経由する Zigbee や Z-Wave の機器はハブの MAC にまとめられてしまう。

### YourThings

- **引用**：Alrawi et al., "SoK: Security Evaluation of Home-Based IoT Deployments," IEEE S&P 2019
- **URL**：https://yourthings.info/data/
- **利用条件**：使ったら論文を引用すること（データのページの記載）。
- **形式**：1 日 1 つの tgz（10〜13GB）。中身は 5 分ごとの PCAP（1 日 288 個）。3 月の分は `2018/03/DD/` と 1 段深い。ファイル名の時刻は、パケットの時刻より 5 時間ずれている（並べる順番には影響しない）。機器と IP の対応表：https://yourthings.info/assets/device_mapping.csv
- **公開されている日**：2018 年 3 月 20・21・28 日、4 月 10〜19 日（計 13 日）。使ったのは 4 月 10〜12 日（E14）。
- **検証できること**：実際の家庭に置いた、ほかのデータにない機器（Ring、August、Nest、Wink、VeraLite など）。見たことのない機器での見逃しの確認に使った。
- **限界**：対応表にはスマートフォンや PC も載っているので、除外が必要（[assessment/yourthings-non-iot-macs.txt](assessment/yourthings-non-iot-macs.txt)）。作成者自身の試験が混ざっている。3 月 20 日の Nessus のスキャン（[assessment/dataset-scanners.txt](assessment/dataset-scanners.txt)）と、4 月 10〜12 日の中間者の試験（発行者 `thing-catcher.gtisc.gatech.edu` の偽の証明書、1024 ビットの RSA、[assessment/dataset-interceptors.txt](assessment/dataset-interceptors.txt)、O12）。どちらも家庭の通信の性質ではないので数えない。HTTP の多い日（3 月 20 日）は、Quarant の機器の識別の再計算が遅く、解析に何時間もかかる（STATUS の既知の問題 10）。

### Deakin IoT Traffic Dataset（2026-10-25 に追加）

- **URL**：doi:10.26187/deakin.28013234.v2（CC BY 4.0）。2023 年 5 月〜2024 年 5 月の 119 日、今の市販機器 24 台（Echo Dot 第 4 世代、Echo Show 8、TP-Link Tapo のカメラ、EZVIZ のカメラ、Tuya のドアベル、Ring のドアベル、Galaxy Watch など）。機器と MAC の対応表（`macAddresses.csv`）つき。
- **形式**：1 日 1 つの PCAP。Linux の cooked 形式（SLL）で、送信元の MAC アドレスしか記録されていない。
- **注意**：IoT 機器だけに絞った版（`pcapIoT`、`IoT_*.pcap`、31.6GB）は、**機器が送ったパケットしか入っていない**。外から機器へのパケットがなく、TLS のサーバーの応答（選ばれた版）も見えない。2026-10-25 に全日を解析して気づき、使わないことにした。両方向を含む版（`pcapFull`、82.6GB）は 2023 年 7 月下旬〜9 月と 2024 年 3 月末〜5 月だけ公開されている。そのうち実験に使う 34 日分（28.1GB）を取得した（2024-05-15 は公開されていない）。
- **ネットワーク**：家庭内は 192.168.1.0/24、ゲートウェイは 192.168.1.1（TP-Link、MAC 54:af:97:56:4d:dd）。`pcapFull` にはルーターの外側（大学のネットワーク 10.x、NAT 後の 10.144.96.65）のパケットも入っている。外側のパケットはルーターの MAC から出るので、対応表にない MAC をすべて IoT ではないとして除けば、機器ごとの数には混ざらない（`oss-work/deakin/non-iot-macs.txt`、26 個）。対応表の 24 台のうち、34 日で通信が見えたのは 19 台。

## 見送ったデータセットと理由

| データセット | 理由 |
|---|---|
| N-BaIoT（UCI） | 特徴量 CSV だけで、PCAP がない |
| CICIoT2023 / CIC IoT-DIAD 2024 | 容量が非常に大きい。Mirai はフラッド攻撃だけでスキャンの段階がない。DIAD は PCAP の提供が未確認。Recon と Spoofing のファイルは Phase 2 の補助候補として残す |
| Bot-IoT / TON_IoT | Cyber Range 上の模擬 IoT で、家庭 LAN の識別情報がない。利用は学術目的に限られる。スキャンのラベルは補助候補 |
| Mon(IoT)r IMC'19 | 実機 81 台で、平文での情報露出の正解として最も強い。ただしデータ共有契約が必要で、機関の外に出せず、機密保持の義務もある。リポジトリやテストには使えない。平文検出の評価が必要になった段階で、利用者が申請するかを判断する |
| YourThings | 手作業の脆弱性評価が「パッシブ監視で見逃したこと」の正解になり得る。ただし正式なライセンスがなく、IP と機器の対応しかない。Phase 2 の候補 |
| IoT Sentinel | セットアップ時の通信だけ。ライセンスが明記されていない。DHCP 指紋の補助候補 |
| MQTT-IoT-IDS2020 / IoT Network Intrusion（Kang） | ライセンスが明記されていない（未確認）。MQTT の認証情報と、Telnet のブルートフォースの小規模な確認には有用。利用前に条件を確認する |

## どのデータセットでも測れないこと

- **ファームウェアと CVE の正解**：公開データセットにない。I5 の照合は、引き続き「適用可否は未確認」とする。
- **TLS 1.3 の証明書**：暗号化されているため検査できない。
- **ハブ配下の機器**：Zigbee や Z-Wave の機器は見えない。
- **実環境での感染**：ラボで生成した攻撃は、実際の感染とは違う。IoT-23 が最も近い。
- **ラベルの粒度**：ファイル単位や flow 単位のラベルを Quarant のイベントと結合するときに誤差が出る。

## データの取り扱い

- ダウンロードしたデータは**リポジトリの外**に置く（例：`~/datasets/`）。
  - `.gitignore` で `*.pcap` と `runs/` を除外済み。
  - IoT-23 と CIC は引用すれば再配布できるが、容量の点からもリポジトリには入れない。
- 実験ごとに、データセット名、ファイル名、SHA-256、Quarant のコミットを記録する（[EVALUATION.md](EVALUATION.md)）。
- 引用の条件：
  - 論文と発表資料では、上の引用を必ず付ける。
  - CIC は「データセットと論文の両方」を引用する。
  - IoT-23 は CC BY に従ってクレジットを表示する。

## 取得と評価の状況（2026-10-17）

| データセット | 取得したもの | 評価 |
|---|---|---|
| UNSW IoT traces | 20 日分すべて（6.4GB）と機器一覧 | 済み（[EXPERIMENTS.md](EXPERIMENTS.md) E1-2） |
| UNSW IoT attack traces | ARP スプーフィングを含む 5 日分（約 9.5GB）と注釈 | 済み（E1-3） |
| IoT-23 | 悪性 6 シナリオと正常 2 シナリオ（PCAP、ラベル、README のみ。マルウェア本体は取得していない） | 済み（E1-1） |
| CIC IoT 2022 | 未取得（登録フォームが必要） | 未実施 |
