#!/bin/bash
# O12: re-run only the Zeek path on YourThings 2018 (the evidence script now
# logs the certificate issuer), keeping Quarant's q/ as is, and re-merge.
# Days are extracted from the USB drive one at a time and removed after.
set -u
Q=$HOME/datasets/oss-work/quarant-oss
OUT=$HOME/datasets/runs-oss1
log() { echo "$(date '+%m-%d %H:%M:%S') $*" >> $OUT/progress.log; }
for day in 20180320 20180410 20180411 20180412; do
  o=$OUT/yt-$day; [ -f $o/rezeek-done ] && continue
  src=$HOME/datasets/yt-extract/$day
  rm -rf $src; mkdir -p $src; tar -xzf /Volumes/Untitled/iot_traffic$day.tgz -C $src || { log "yt-$day: extract failed"; continue; }
  rm -rf $o/zparts; mkdir -p $o/zparts
  find $src -type f -name 'eth1-*' | sort | xargs -P 6 -n 1 $HOME/datasets/oss-work/zeek1.sh $o/zparts
  cat $(find $o/zparts -name quarant_evidence.log | sort) > $o/quarant_evidence.log
  rm -rf $o/zparts $o/z $o/m
  $Q zeek evidence --log $o/quarant_evidence.log --out $o/z > $o/z.log 2>&1
  $Q merge --quarant $o/q --zeek $o/z --out $o/m > $o/m.log 2>&1
  touch $o/rezeek-done; rm -rf $src
  log "yt-$day rezeek done"
done
log "rezeek all done"
