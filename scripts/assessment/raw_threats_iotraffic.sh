#!/bin/bash
# O10: count path threats on the O9 windows with an independent parser
# (raw_threats.py), before and after each condition; filter statistics with
# per-device counts.
set -u
OUT=$HOME/datasets/oss-work/iot-cm-run
Q=$HOME/datasets/oss-work/quarant-oss
REPO=$HOME/Desktop/Quarant-oss
PC=$HOME/datasets/raw/unsw-iotraffic/pcaps
NONIOT=$HOME/datasets/oss-work/iot-cm/non-iot-macs.txt
RT="python3 -I $REPO/scripts/assessment/raw_threats.py"
GW=192.168.1.1
log() { echo "$(date '+%m-%d %H:%M:%S') $*" >> $OUT/raw-progress.log; }
epoch() { python3 -c "import datetime,sys;print(int(datetime.datetime.strptime(sys.argv[1],'%Y-%m-%d').replace(tzinfo=datetime.timezone.utc).timestamp()))" "$1"; }
window() {
  local d=$OUT/$1; [ -s $d/capture.pcap ] && return
  mkdir -p $d/parts; local a b; a=$(epoch $2); b=$(epoch $3)
  for f in $PC/*; do editcap -F pcap -A $a -B $b "$f" $d/parts/$(basename "$f" | sed 's/\.pcapng$/.pcap/') 2>/dev/null; done
  find $d/parts -name '*.pcap' -size -25c -delete
  mergecap -F pcap -w $d/dup.pcap $d/parts/*.pcap && editcap -F pcap -D 100 $d/dup.pcap $d/capture.pcap > /dev/null 2>&1
  rm -rf $d/parts $d/dup.pcap
}
L=$OUT/learn
for spec in m1:2016-11-07:2016-11-14 m2:2016-11-28:2016-12-04 m3:2017-01-09:2017-01-16 m4:2017-02-06:2017-02-13 m5:2017-03-06:2017-03-13; do
  IFS=: read name s e <<< "$spec"
  window $name $s $e; T=$OUT/$name
  [ -s $T/base/raw.json ] || $RT $T/capture.pcap $T/base/raw.json --exclude $NONIOT
  for v in "router:$L/plan.json:router_default" \
           "router+vlan:$L/plan.json:router_default,isolate_iot" \
           "router+ports:$L/plan.json:router_default,block_cleartext_ports" \
           "router+allow:$L/allow.json:router_default,allowlist" \
           "router+quarant:$L/plan.json:router_default,block_inbound,block_weak_destinations,isolate" \
           "router+quarant-broad:$L/plan.json:router_default,block_inbound,block_weak_ports,isolate" \
           "router+quarant-same:$T/plan-same.json:router_default,block_inbound,block_weak_destinations,isolate"; do
    IFS=: read vn plan apply <<< "$v"
    V=$T/$vn; [ -s $V/raw.json ] && continue
    $Q countermeasure filter --plan $plan --apply $apply --gateway $GW --non-iot-macs $NONIOT --out - --stats $V/filter2.stats.json $T/capture.pcap 2>/dev/null \
      | $RT - $V/raw.json --exclude $NONIOT
  done
  rm -f $T/capture.pcap
  log "$name done"
done
log "all done"
