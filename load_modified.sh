#!/usr/bin/env bash

for i in "modified" "recent"; do
  wget "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-$i.json.gz"
  gzip -d "nvdcve-1.1-$i.json.gz"
  cat nvdcve-1.1-$i.json | jq -c '.CVE_Items[]' > nvdcve-1.1-$i-l.json
  rm nvdcve-1.1-$i.json
done
