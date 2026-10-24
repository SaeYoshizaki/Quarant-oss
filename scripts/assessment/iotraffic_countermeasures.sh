#!/bin/bash
# O9: countermeasures on UNSW-IoTraffic with learning and protection months apart.
# Learn (Quarant plan, allowlist) on one window, apply to later windows.
# usage: iotraffic-cm.sh OUTDIR LEARN_START LEARN_END NAME:START:END...   (dates YYYY-MM-DD, UTC)
set -u
OUT=$1; shift; LS=$1; LE=$2; shift 2
Q=$HOME/datasets/oss-work/quarant-oss
REPO=$HOME/Desktop/Quarant-oss
ZS=$REPO/internal/zeekevidence/evidence.zeek
PC=$HOME/datasets/raw/unsw-iotraffic/pcaps
CM=$HOME/datasets/oss-work/iot-cm
NONIOT=$CM/non-iot-macs.txt
GW=192.168.1.1
mkdir -p $OUT
log() { echo "$(date '+%m-%d %H:%M:%S') $*" >> $OUT/progress.log; }
epoch() { python3 -c "import datetime,sys;print(int(datetime.datetime.strptime(sys.argv[1],'%Y-%m-%d').replace(tzinfo=datetime.timezone.utc).timestamp()))" "$1"; }

# window NAME START END: cut every device capture to [START, END) and merge them
# into one home capture; packets between two IoT devices appear in both
# devices' files, so duplicates are removed after the merge.
window() {
  local d=$OUT/$1; [ -s $d/capture.pcap ] && return
  rm -rf $d; mkdir -p $d/parts
  local a b; a=$(epoch $2); b=$(epoch $3)
  for f in $PC/*; do
    editcap -F pcap -A $a -B $b "$f" $d/parts/$(basename "$f" | sed 's/\.pcapng$/.pcap/') 2>/dev/null
  done
  find $d/parts -name '*.pcap' -size -25c -delete
  mergecap -F pcap -w $d/dup.pcap $d/parts/*.pcap && editcap -F pcap -D 100 $d/dup.pcap $d/capture.pcap > $d/dedup.txt 2>&1
  rm -rf $d/parts $d/dup.pcap
  log "window $1 $2..$3: $(capinfos -c -M $d/capture.pcap | grep 'Number of packets' | tr -s ' ')"
}

# analyse DIR CAPTURE_STREAM_CMD...: Quarant and Zeek on a capture, then merge
analyse() {
  local d=$1; shift
  mkdir -p $d/q $d/zraw
  ( "$@" 2>$d/filter.txt | $Q analyze - --out $d/q/events.jsonl --flows-out /dev/null --observations-out=- > $d/q/quarant.log 2>&1 ) &
  ( "$@" 2>/dev/null | ( cd $d/zraw && zeek -C -r - $ZS LogAscii::use_json=T > zeek.stderr 2>&1 ) ) &
  wait
  $Q zeek evidence --log $d/zraw/quarant_evidence.log --out $d/zeek > $d/zeek-summary.txt 2>&1
  mv $d/zraw/quarant_evidence.log $d/ 2>/dev/null; rm -rf $d/zraw
  $Q merge --quarant $d/q --zeek $d/zeek --out $d/m > /dev/null 2>&1
}

window learn $LS $LE
L=$OUT/learn
if [ ! -f $L/base/done ]; then
  rm -rf $L/base; analyse $L/base cat $L/capture.pcap; touch $L/base/done
fi
$Q countermeasure plan --events $L/base/m/events.jsonl --evidence-map $REPO/docs/assessment/evidence-map.json --non-iot-macs $NONIOT --out $L/plan.json > $L/plan.txt
$Q countermeasure learn --gateway $GW --non-iot-macs $NONIOT --out $L/allow.json $L/capture.pcap > $L/allow.txt
log "learned: $(head -1 $L/plan.txt) / $(cat $L/allow.txt)"

for spec in "$@"; do
  IFS=: read name s e <<< "$spec"
  window $name $s $e
  T=$OUT/$name
  [ -f $T/base/done ] || { rm -rf $T/base; analyse $T/base cat $T/capture.pcap; touch $T/base/done; }
  $Q countermeasure plan --events $T/base/m/events.jsonl --evidence-map $REPO/docs/assessment/evidence-map.json --non-iot-macs $NONIOT --out $T/plan-same.json > /dev/null
  for v in "router:$L/plan.json:router_default" \
           "router+vlan:$L/plan.json:router_default,isolate_iot" \
           "router+ports:$L/plan.json:router_default,block_cleartext_ports" \
           "router+allow:$L/allow.json:router_default,allowlist" \
           "router+quarant:$L/plan.json:router_default,block_inbound,block_weak_destinations,isolate" \
           "router+quarant-broad:$L/plan.json:router_default,block_inbound,block_weak_ports,isolate" \
           "router+quarant-same:$T/plan-same.json:router_default,block_inbound,block_weak_destinations,isolate"; do
    IFS=: read vn plan apply <<< "$v"
    V=$T/$vn; [ -f $V/done ] && continue
    rm -rf $V; mkdir -p $V
    analyse $V $Q countermeasure filter --plan $plan --apply $apply --gateway $GW --non-iot-macs $NONIOT --out - --stats $V/filter.stats.json $T/capture.pcap
    touch $V/done
  done
  args=()
  for vn in router router+vlan router+ports router+allow router+quarant router+quarant-broad router+quarant-same; do
    args+=("$vn=$T/$vn/m@$T/$vn/filter.stats.json")
  done
  python3 -I $REPO/scripts/assessment/countermeasure_effect.py $REPO/docs/assessment/evidence-map.json $NONIOT $T/effect.md $T/base/m "${args[@]}" --names $CM/names.json > /dev/null 2>$T/effect.err
  log "$name done"
done
log "all done"
