#!/bin/bash
# O13: countermeasures on Deakin (pcapFull, 2023-24), learning on one week and
# protecting weeks up to ten months later. Like iotraffic-cm.sh (O9) and
# raw-threats-o9.sh (O10) together: each filtered stream goes once through
# Quarant, Zeek and the independent count (raw_threats.py). Windows are lists
# of daily files read in order; no merged capture is written.
set -u
OUT=$HOME/datasets/oss-work/deakin-cm-run
Q=$HOME/datasets/oss-work/quarant-oss
REPO=$HOME/Desktop/Quarant-oss
ZS=$REPO/internal/zeekevidence/evidence.zeek
PCAT="python3 -I $REPO/scripts/accuracy/pcapcat.py"
RT="python3 -I $REPO/scripts/assessment/raw_threats.py"
PC=$HOME/datasets/raw/deakin-iot/pcapFull
CM=$HOME/datasets/oss-work/deakin
NONIOT=$CM/non-iot-macs.txt
EMAP=$REPO/docs/assessment/evidence-map.json
GW=192.168.1.1
mkdir -p $OUT
log() { echo "$(date '+%m-%d %H:%M:%S') $*" >> $OUT/progress.log; }
win() { python3 - "$PC" "$1" "$2" <<'PY'
import sys,os,datetime as d
pc,a,b=sys.argv[1:]
x=d.date.fromisoformat(a); y=d.date.fromisoformat(b)
while x<=y:
    p=os.path.join(pc,x.isoformat()+'.pcap')
    if os.path.exists(p): print(p)
    x+=d.timedelta(days=1)
PY
}

# consume DIR: read a pcap stream on stdin; Quarant, Zeek and raw_threats in parallel
consume() {
  local d=$1; mkdir -p $d/q $d/zraw; rm -f $d/fq $d/fz; mkfifo $d/fq $d/fz
  $Q analyze - --out $d/q/events.jsonl --flows-out /dev/null --observations-out=- < $d/fq > $d/q/quarant.log 2>&1 &
  ( cd $d/zraw && zeek -C -r - $ZS LogAscii::use_json=T < ../fz > zeek.stderr 2>&1 ) &
  tee $d/fq $d/fz | $RT - $d/raw.json --exclude $NONIOT
  wait
  rm -f $d/fq $d/fz
  $Q zeek evidence --log $d/zraw/quarant_evidence.log --out $d/zeek > $d/zeek-summary.txt 2>&1
  mv $d/zraw/quarant_evidence.log $d/ 2>/dev/null; rm -rf $d/zraw
  $Q merge --quarant $d/q --zeek $d/zeek --out $d/m > /dev/null 2>&1
}

L=$OUT/learn
LF=$(win 2023-07-26 2023-08-01)
if [ ! -f $L/base/done ]; then
  rm -rf $L/base; mkdir -p $L/base; $PCAT $LF | consume $L/base; touch $L/base/done
fi
$Q countermeasure plan --events $L/base/m/events.jsonl --evidence-map $EMAP --non-iot-macs $NONIOT --out $L/plan.json > $L/plan.txt
$Q countermeasure learn --gateway $GW --non-iot-macs $NONIOT --out $L/allow.json $LF > $L/allow.txt
log "learned: $(head -1 $L/plan.txt) / $(cat $L/allow.txt)"

for spec in w1:2023-08-14:2023-08-20 w2:2023-08-31:2023-09-06 w3:2024-04-08:2024-04-14 w4:2024-05-13:2024-05-19; do
  IFS=: read name s e <<< "$spec"
  T=$OUT/$name; mkdir -p $T; TF=$(win $s $e)
  [ -f $T/base/done ] || { rm -rf $T/base; mkdir -p $T/base; $PCAT $TF | consume $T/base; touch $T/base/done; }
  $Q countermeasure plan --events $T/base/m/events.jsonl --evidence-map $EMAP --non-iot-macs $NONIOT --out $T/plan-same.json > /dev/null
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
    $Q countermeasure filter --plan $plan --apply $apply --gateway $GW --non-iot-macs $NONIOT --out - --stats $V/filter.stats.json $TF 2>$V/filter.txt | consume $V
    cp $V/filter.stats.json $V/filter2.stats.json
    touch $V/done
  done
  args=()
  for vn in router router+vlan router+ports router+allow router+quarant router+quarant-broad router+quarant-same; do
    args+=("$vn=$T/$vn/m@$T/$vn/filter.stats.json")
  done
  python3 -I $REPO/scripts/assessment/countermeasure_effect.py $EMAP $NONIOT $T/effect.md $T/base/m "${args[@]}" --names $CM/names.json > /dev/null 2>$T/effect.err
  log "$name done"
done
python3 -I $REPO/scripts/assessment/raw_effect.py $OUT/raw-effect.md $CM/names.json $OUT/w1 $OUT/w2 $OUT/w3 $OUT/w4 > /dev/null
log "all done"
