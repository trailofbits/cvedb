#!/usr/bin/env bash

set -e

YEAR=`date +'%Y'`

for y in $(seq $YEAR -1 2002); do
  wget -N https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-$y.meta
  wget -N https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-$y.json.gz
done
