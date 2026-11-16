#!/usr/bin/env bash

set -euo pipefail

year=$(date +'%Y')

for ((y = year; y >= 2002; y--)); do
  wget -N "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-$y.meta"
  wget -N "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-$y.json.gz"
done
