# 確認 D：OSS から足した検出の正しさ（O11）

OSS（Zeek）から足した検出（D27、D28）が、規格の要件の証拠として正しいかを、抜き取りで判定した。E4 と同じく、検出の種類ごとに最大 15 件を無作為に抜き出した（乱数の種 20261025）。同じ機器が何度も出ないよう、機器ごとに 1 件を代表にした。IoT ではない機器（スマートフォン、PC、ルーター）は除いた。

## 確認のしかた

- 各件について、Claude の判定と理由を読んで、**容認する**か**変更する**にチェックを付ける。変更する場合は、メモ欄にどう変えるかを書く。
- 判定の途中で見つけた問題は、すでに直してある（各件の理由に「直した」と書いたもの）。

## 集計（Claude の判定）

| 検出 | 抜き取り | 正しい | 数えない・誤り | 直したこと |
|---|---|---|---|---|
| 弱い証明書（5.1-3、5.5-1） | 15 | 9 | 6 | 機器が受け取る側でハンドシェイクが終わっていないものは数えない。機器自身がサーバーなら数える |
| 弱い SSH（5.1-3、5.5-1） | 1 | 1 | 0 | — |
| SNMP の初期のコミュニティ名（5.1-1、5.1-2、5.5-6） | 1 | 1 | 0 | — |
| 版の開示（5.6-2） | 15 | 14 | 1 | 版がすべて 0 なら数えない |
| 脆弱性のある版の候補（5.2-2、5.3-8） | 10 | 9 | 1 | 配布版（Ubuntu など）を名乗る SSH は確度を下げる |

機器の数で見ると、抜き取りの母数は、弱い証明書 48 台、弱い SSH 1 台、SNMP 1 台、版の開示 75 台、脆弱性のある版 10 台（IoT 機器、全データ）。

---

## 弱い証明書（5.1-3、5.5-1）

### 1. WithingsHome（yt-20180411）

- 通信：192.168.0.32 → 89.30.121.150:443
- 根拠：`risk_kind=weak_certificate_key key=rsa1024 self_signed=false established=false src=192.168.0.32:44934 dst=89.30.121.150:443 peer=scalews.withings.net`
- Claude の判定：**数えない**
- 理由：ハンドシェイクが終わっておらず、機器（受け取る側）が証明書を受け入れたか分からない。直したあとは確度 low
- [ ] 容認する
- [ ] 変更する
- メモ：

### 2. D-LinkDCS-5009LCamera（yt-20180320）

- 通信：192.168.0.200 → 192.168.0.28:443
- 根拠：`risk_kind=weak_certificate_key key=rsa1024 self_signed=true established=false src=192.168.0.200:54674 dst=192.168.0.28:443 peer=192.168.0.28`
- Claude の判定：**正しい**
- 理由：機器（D-Link のカメラ）自身がサーバーとして RSA 1024 ビットの自己署名の証明書を出している。相手（データセットの検査用ツール）がハンドシェイクを終えたかに関係なく、機器の弱点。最初は数えない扱いで、直した
- [ ] 容認する
- [ ] 変更する
- メモ：

### 3. HPPrinter（unsw-16-09-24）

- 通信：192.168.1.236 → 15.72.255.53:5223
- 根拠：`risk_kind=weak_certificate_signature signature=sha1WithRSAEncryption self_signed=false established=true src=192.168.1.236:55056 dst=15.72.255.53:5223 peer=15.72.255.53`
- Claude の判定：**正しい**
- 理由：HP のプリンターが、SHA-1 で署名された接続先の証明書を受け入れて通信を続けた
- [ ] 容認する
- [ ] 変更する
- メモ：

### 4. AppleHomePod（yt-20180410）

- 通信：192.168.0.138 → 192.168.0.47:49367
- 根拠：`risk_kind=weak_certificate_key key=rsa1024 self_signed=true established=true src=192.168.0.138:53499 dst=192.168.0.47:49367 peer=192.168.0.47`
- Claude の判定：**正しい**
- 理由：HomePod 自身が、家庭内の接続（AirPlay と思われる）で RSA 1024 ビットの自己署名の証明書を出している
- [ ] 容認する
- [ ] 変更する
- メモ：

### 5. LogitechHarmonyHub（yt-20180411）

- 通信：192.168.0.39 → 52.54.179.179:443
- 根拠：`risk_kind=weak_certificate_key key=rsa1024 self_signed=false established=true src=192.168.0.39:50369 dst=52.54.179.179:443 peer=52.54.179.179`
- Claude の判定：**正しい（要確認）**
- 理由：Harmony Hub が、RSA 1024 ビットの接続先の証明書を受け入れた。YourThings の作成者の中間者の試験の証明書だった可能性があり、その場合は「証明書を確かめていない」証拠になる
- [ ] 容認する
- [ ] 変更する
- メモ：

### 6. Wink2Hub（yt-20180320）

- 通信：192.168.0.200 → 192.168.0.52:8888
- 根拠：`risk_kind=weak_certificate_key key=rsa1024 self_signed=true established=true src=192.168.0.200:38540 dst=192.168.0.52:8888 peer=192.168.0.52`
- Claude の判定：**正しい**
- 理由：Wink 2 Hub 自身が、RSA 1024 ビットの自己署名の証明書を出している
- [ ] 容認する
- [ ] 変更する
- メモ：

### 7. SamsungSmartTV（yt-20180410）

- 通信：192.168.0.49 → 35.160.184.21:443
- 根拠：`risk_kind=weak_certificate_key key=rsa1024 self_signed=false established=false src=192.168.0.49:52902 dst=35.160.184.21:443 peer=osb-apps.samsungqbe.com`
- Claude の判定：**数えない**
- 理由：ハンドシェイクが終わっていない（受け取る側）
- [ ] 容認する
- [ ] 変更する
- メモ：

### 8. AugustDoorBell（iot-AugustDoorBell_e076d03f00ae）

- 通信：192.168.1.216 → 104.239.245.188:443
- 根拠：`risk_kind=weak_certificate_signature signature=sha1WithRSAEncryption self_signed=false established=true src=192.168.1.216:34566 dst=104.239.245.188:443 peer=iconfig.august.com`
- Claude の判定：**正しい**
- 理由：August のドアベルが、SHA-1 で署名された接続先の証明書を受け入れて通信を続けた
- [ ] 容認する
- [ ] 変更する
- メモ：

### 9. Canary（yt-20180411）

- 通信：192.168.0.30 → 52.200.251.249:443
- 根拠：`risk_kind=weak_certificate_key key=rsa1024 self_signed=false established=false src=192.168.0.30:57640 dst=52.200.251.249:443 peer=i.canaryis.com`
- Claude の判定：**数えない**
- 理由：ハンドシェイクが終わっていない（受け取る側）
- [ ] 容認する
- [ ] 変更する
- メモ：

### 10. PixStarPhotoFrame（iot-PixStarPhotoFrame_e076d033bb85）

- 通信：192.168.1.177 → 176.31.232.79:443
- 根拠：`risk_kind=weak_certificate_signature signature=sha1WithRSAEncryption self_signed=false established=true src=192.168.1.177:57935 dst=176.31.232.79:443 peer=api.pix-star.com`
- Claude の判定：**正しい**
- 理由：Pix-Star の写真立てが、SHA-1 で署名された接続先の証明書を受け入れて通信を続けた
- [ ] 容認する
- [ ] 変更する
- メモ：

### 11. AmazonEchoGen1（yt-20180411）

- 通信：192.168.0.15 → 52.46.156.66:443
- 根拠：`risk_kind=weak_certificate_key key=rsa1024 self_signed=false established=false src=192.168.0.15:58655 dst=52.46.156.66:443 peer=52.46.156.66`
- Claude の判定：**数えない**
- 理由：ハンドシェイクが終わっていない。Amazon の接続先が RSA 1024 ビットなのは 2018 年として不自然で、中間者の試験の証明書を拒んだ可能性がある
- [ ] 容認する
- [ ] 変更する
- メモ：

### 12. TribySpeaker（iot-TribySpeaker_18B79E022044）

- 通信：192.168.1.120 → 188.165.38.151:443
- 根拠：`risk_kind=weak_certificate_key key=rsa1024 risk_kind=weak_certificate_signature signature=sha1WithRSAEncryption self_signed=false established=true src=192.168.1.120:57057 dst=188.165.38.151:443 peer=w`
- Claude の判定：**正しい**
- 理由：Triby のスピーカーが、RSA 1024 ビットで SHA-1 の接続先の証明書を受け入れて通信を続けた
- [ ] 容認する
- [ ] 変更する
- メモ：

### 13. HarmonKardonInvoke（yt-20180412）

- 通信：192.168.0.45 → 104.208.28.54:443
- 根拠：`risk_kind=weak_certificate_key key=rsa1024 self_signed=false established=false src=192.168.0.45:49326 dst=104.208.28.54:443 peer=mobile.pipe.aria.microsoft.com`
- Claude の判定：**数えない**
- 理由：ハンドシェイクが終わっていない（受け取る側）
- [ ] 容認する
- [ ] 変更する
- メモ：

### 14. BelkinNetcam（yt-20180411）

- 通信：192.168.0.18 → 23.23.141.53:8443
- 根拠：`risk_kind=weak_certificate_key key=rsa1024 self_signed=false established=false src=192.168.0.18:50501 dst=23.23.141.53:8443 peer=api.xbcs.net`
- Claude の判定：**数えない**
- 理由：ハンドシェイクが終わっていない（受け取る側）
- [ ] 容認する
- [ ] 変更する
- メモ：

### 15. TribySpeaker（unsw-16-10-09）

- 通信：192.168.1.120 → 188.165.38.151:443
- 根拠：`risk_kind=weak_certificate_key key=rsa1024 risk_kind=weak_certificate_signature signature=sha1WithRSAEncryption self_signed=false established=true src=192.168.1.120:54786 dst=188.165.38.151:443 peer=w`
- Claude の判定：**正しい**
- 理由：12 と同じ機器（UNSW 2016）
- [ ] 容認する
- [ ] 変更する
- メモ：

## 弱い SSH（5.1-3、5.5-1）

### 1. MiCasaVerdeVeraLite（yt-20180411）

- 通信：192.168.0.34 → 54.187.71.199:232
- 根拠：`risk_kind=weak_ssh_kex kex=diffie-hellman-group1-sha1 ssh_server="SSH-2.0-remote_connection1.0" src=192.168.0.34:54728 dst=54.187.71.199:232 peer=54.187.71.199`
- Claude の判定：**正しい**
- 理由：VeraLite がメーカーのクラウドへの SSH で diffie-hellman-group1-sha1 を使った。RFC 9142 で SHOULD NOT
- [ ] 容認する
- [ ] 変更する
- メモ：

## SNMP の初期のコミュニティ名（5.1-1、5.1-2、5.5-6）

### 1. HPPrinter（iot-HPPrinter_705a0fe49bc0）

- 通信：192.168.1.243 → 192.168.1.236:161
- 根拠：`snmp_default_community=*** snmp_version=1 responses=1 src=192.168.1.243:62950 dst=192.168.1.236:161 peer=192.168.1.236`
- Claude の判定：**正しい**
- 理由：HP のプリンターが、コミュニティ名 public の SNMP の要求に応答した（初期の認証情報を受け入れている）
- [ ] 容認する
- [ ] 変更する
- メモ：

## 版の開示（5.6-2）

### 1. 1c:12:b0:9b:0c:ec（cic-2-idle-2021_12_09_Idle）

- 通信：192.168.137.217 → —:—
- 根拠：`software_type=DHCP::CLIENT name="dhcpcd" version=5.5.6 host=192.168.137.217`
- Claude の判定：**正しい**
- 理由：DHCP のベンダークラスに dhcpcd 5.5.6。プロトコルは版を求めていない
- [ ] 容認する
- [ ] 変更する
- メモ：

### 2. 44:01:bb:ec:10:4a（cic-2-idle-2021_11_03_Idle）

- 通信：192.168.137.141 → —:—
- 根拠：`software_type=DHCP::CLIENT name="udhcp" version=0.9.9 host=192.168.137.141`
- Claude の判定：**正しい**
- 理由：udhcp 0.9.9（古い単独の udhcp）
- [ ] 容認する
- [ ] 変更する
- メモ：

### 3. 08:7c:39:ce:6e:2a（cic-2-idle-2021_11_18_Idle）

- 通信：192.168.137.231 → —:—
- 根拠：`software_type=DHCP::CLIENT name="android-dhcp" version=7.1.2 host=192.168.137.231`
- Claude の判定：**正しい**
- 理由：android-dhcp 7.1.2（Android の版）
- [ ] 容認する
- [ ] 変更する
- メモ：

### 4. 44:bb:3b:00:39:07（cic-2-idle-2021_11_04_Idle）

- 通信：192.168.137.143 → —:—
- 根拠：`software_type=DHCP::CLIENT name="udhcp" version=1.19.3 host=192.168.137.143`
- Claude の判定：**正しい**
- 理由：udhcp 1.19.3
- [ ] 容認する
- [ ] 変更する
- メモ：

### 5. GoogleHome（yt-20180410）

- 通信：192.168.0.43 → —:—
- 根拠：`software_type=DHCP::CLIENT name="dhcpcd" version=5.2.10 host=192.168.0.43`
- Claude の判定：**正しい**
- 理由：Google Home の dhcpcd 5.2.10
- [ ] 容認する
- [ ] 変更する
- メモ：

### 6. PixStarPhotoFrame（iot-PixStarPhotoFrame_e076d033bb85）

- 通信：192.168.1.177 → —:—
- 根拠：`software_type=DHCP::CLIENT name="udhcp" version=1.21.1 host=192.168.1.177`
- Claude の判定：**正しい**
- 理由：udhcp 1.21.1
- [ ] 容認する
- [ ] 変更する
- メモ：

### 7. Wink2Hub（yt-20180410）

- 通信：192.168.0.52 → —:—
- 根拠：`software_type=DHCP::CLIENT name="udhcp" version=1.24.2 host=192.168.0.52`
- Claude の判定：**正しい**
- 理由：udhcp 1.24.2
- [ ] 容認する
- [ ] 変更する
- メモ：

### 8. NestDropCam（iot-NestDropCam_308cfb2fe4b2）

- 通信：192.168.1.106 → —:—
- 根拠：`software_type=DHCP::CLIENT name="udhcp" version=1.19.3 host=192.168.1.106`
- Claude の判定：**正しい**
- 理由：udhcp 1.19.3
- [ ] 容認する
- [ ] 変更する
- メモ：

### 9. ChineseWebcam（yt-20180411）

- 通信：192.168.0.35 → —:—
- 根拠：`software_type=HTTP::SERVER name="uc-httpd" version=1.0.0 host=192.168.0.35`
- Claude の判定：**正しい**
- 理由：中国製の Web カメラの Web サーバーが uc-httpd 1.0.0 を名乗る
- [ ] 容認する
- [ ] 変更する
- メモ：

### 10. WithingsSmartScale（unsw-16-10-09）

- 通信：192.168.1.238 → —:—
- 根拠：`software_type=DHCP::CLIENT name="Withings" version=0 host=192.168.1.238`
- Claude の判定：**誤り**
- 理由：「Withings 0」は版ではなく名前の後ろの 0。直した（版の部分がすべて 0 なら数えない）
- [ ] 容認する
- [ ] 変更する
- メモ：

### 11. WithingsBabyMonitor（unsw-16-10-06）

- 通信：192.168.1.166 → —:—
- 根拠：`software_type=DHCP::CLIENT name="udhcp" version=1.15.1 host=192.168.1.166`
- Claude の判定：**正しい**
- 理由：udhcp 1.15.1
- [ ] 容認する
- [ ] 変更する
- メモ：

### 12. SamsungCamera（iot-SamsungCamera_00166cab6b88）

- 通信：192.168.1.249 → —:—
- 根拠：`software_type=DHCP::CLIENT name="udhcp" version=1.19.4 host=192.168.1.249`
- Claude の判定：**正しい**
- 理由：udhcp 1.19.4
- [ ] 容認する
- [ ] 変更する
- メモ：

### 13. NestCamera（yt-20180410）

- 通信：192.168.0.10 → —:—
- 根拠：`software_type=DHCP::CLIENT name="udhcp" version=1.19.3 host=192.168.0.10`
- Claude の判定：**正しい**
- 理由：udhcp 1.19.3
- [ ] 容認する
- [ ] 変更する
- メモ：

### 14. 10:2c:6b:1b:43:be（cic-1-power-simcamPOWER_3）

- 通信：192.168.137.222 → —:—
- 根拠：`software_type=DHCP::CLIENT name="udhcp" version=1.30.1 host=192.168.137.222`
- Claude の判定：**正しい**
- 理由：udhcp 1.30.1
- [ ] 容認する
- [ ] 変更する
- メモ：

### 15. PhilipsHue（iot-PhilipsHue_0017882b9a25）

- 通信：192.168.1.159 → —:—
- 根拠：`software_type=DHCP::CLIENT name="udhcp" version=1.19.4 host=192.168.1.159`
- Claude の判定：**正しい**
- 理由：udhcp 1.19.4
- [ ] 容認する
- [ ] 変更する
- メモ：

## 脆弱性のある版の候補（5.2-2、5.3-8）

### 1. CasetaWirelessHub（yt-20180320）

- 通信：192.168.0.41 → —:—
- 根拠：`software_type=SSH::SERVER name="OpenSSH" version=7.5 cpe=openbsd:openssh cve_count=1 kev_count=0 oldest_days=145 cves=CVE-2017-15906(medium,145d) knowledge=component_cves.json@2026-10-21 host=192.168.`
- Claude の判定：**候補として正しい**
- 理由：OpenSSH 7.5 と CVE-2017-15906（sftp-server の読み取り専用の回避）。SFTP を使っていなければ当たらない
- [ ] 容認する
- [ ] 変更する
- メモ：

### 2. GoogleHomeMini（yt-20180320）

- 通信：192.168.0.42 → —:—
- 根拠：`software_type=DHCP::CLIENT name="dhcpcd" version=5.2.10 cpe=roy_marples:dhcpcd cve_count=1 kev_count=0 oldest_days=2533 cves=CVE-2011-0996(medium,2533d) knowledge=component_cves.json@2026-10-21 host=1`
- Claude の判定：**候補として正しい**
- 理由：dhcpcd 5.2.10 と CVE-2011-0996（ホスト名を介したコマンドの実行。dhcpcd のフックの作りによる）
- [ ] 容認する
- [ ] 変更する
- メモ：

### 3. InsteonHub（yt-20180320）

- 通信：192.168.0.6 → —:—
- 根拠：`software_type=SSH::SERVER name="OpenSSH" version=6.6.1 cpe=openbsd:openssh cve_count=15 kev_count=0 oldest_days=960 cves=CVE-2016-1908(critical,343d),CVE-2015-5600(high,960d),CVE-2015-8325(high,688d),`
- Claude の判定：**数えない**
- 理由：「OpenSSH_6.6.1p1 Ubuntu」と名乗っている。Ubuntu の版は番号を変えずに修正を取り込むので、版の番号では判断できない。直した（確度 low）
- [ ] 容認する
- [ ] 変更する
- メモ：

### 4. TPLinkCamera（unsw-16-10-04）

- 通信：192.168.1.143 → —:—
- 根拠：`software_type=HTTP::SERVER name="lighttpd" version=1.4.32 cpe=lighttpd:lighttpd cve_count=7 kev_count=0 oldest_days=1410 cves=CVE-2014-2323(critical,935d),CVE-2013-4559(high,1049d),CVE-2013-4508(high,`
- Claude の判定：**候補として正しい**
- 理由：lighttpd 1.4.32。CVE の多くは特定のモジュール（mod_mysql_vhost など）に限る
- [ ] 容認する
- [ ] 変更する
- メモ：

### 5. NetatmoWelcome（iot-NetatmoWelcome_70ee50183443）

- 通信：192.168.1.241 → —:—
- 根拠：`software_type=HTTP::SERVER name="lighttpd" version=1.4.35 cpe=lighttpd:lighttpd cve_count=1 kev_count=0 oldest_days=519 cves=CVE-2015-3200(high,519d) knowledge=component_cves.json@2026-10-21 host=192.`
- Claude の判定：**候補として正しい**
- 理由：lighttpd 1.4.35 と CVE-2015-3200（mod_auth のログへの書き込み）
- [ ] 容認する
- [ ] 変更する
- メモ：

### 6. NetatmoWelcome（unsw-16-09-28）

- 通信：192.168.1.241 → —:—
- 根拠：`software_type=HTTP::SERVER name="lighttpd" version=1.4.35 cpe=lighttpd:lighttpd cve_count=1 kev_count=0 oldest_days=477 cves=CVE-2015-3200(high,477d) knowledge=component_cves.json@2026-10-21 host=192.`
- Claude の判定：**候補として正しい**
- 理由：5 と同じ機器
- [ ] 容認する
- [ ] 変更する
- メモ：

### 7. TPLinkCamera（iot-TPLinkCamera_f4f26D9351f1）

- 通信：192.168.1.143 → —:—
- 根拠：`software_type=HTTP::SERVER name="lighttpd" version=1.4.32 cpe=lighttpd:lighttpd cve_count=7 kev_count=0 oldest_days=1410 cves=CVE-2014-2323(critical,935d),CVE-2013-4559(high,1049d),CVE-2013-4508(high,`
- Claude の判定：**候補として正しい**
- 理由：4 と同じ機器
- [ ] 容認する
- [ ] 変更する
- メモ：

### 8. MiCasaVerdeVeraLite（yt-20180411）

- 通信：192.168.0.34 → —:—
- 根拠：`software_type=SSH::CLIENT name="dropbear" version=0.53.1 cpe=dropbear_ssh_project:dropbear_ssh cve_count=10 kev_count=0 oldest_days=2136 cves=CVE-2016-7406(critical,404d),CVE-2016-7407(critical,404d),`
- Claude の判定：**候補として正しい**
- 理由：Dropbear 0.53.1 のクライアント。2016 年の CVE にはクライアントに関わるものも含まれる
- [ ] 容認する
- [ ] 変更する
- メモ：

### 9. GoogleHome（yt-20180320）

- 通信：192.168.0.43 → —:—
- 根拠：`software_type=DHCP::CLIENT name="dhcpcd" version=5.2.10 cpe=roy_marples:dhcpcd cve_count=1 kev_count=0 oldest_days=2533 cves=CVE-2011-0996(medium,2533d) knowledge=component_cves.json@2026-10-21 host=1`
- Claude の判定：**候補として正しい**
- 理由：dhcpcd 5.2.10（2 と同じ）
- [ ] 容認する
- [ ] 変更する
- メモ：

### 10. Wink2Hub（yt-20180320）

- 通信：192.168.0.52 → —:—
- 根拠：`software_type=SSH::SERVER name="dropbear" version=2016.73 cpe=dropbear_ssh_project:dropbear_ssh cve_count=6 kev_count=0 oldest_days=382 cves=CVE-2016-7406(critical,382d),CVE-2016-7407(critical,382d),C`
- Claude の判定：**候補として正しい**
- 理由：Dropbear 2016.73 と CVE-2016-7406〜7409（2016.74 で修正）
- [ ] 容認する
- [ ] 変更する
- メモ：
