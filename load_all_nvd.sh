#!/usr/bin/env bash

for i in {2002..2020..1}; do
  echo $i
  wget "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-${i}.json.gz"
  gzip -d "nvdcve-1.1-${i}.json.gz"
  cat nvdcve-1.1-${i}.json | jq -c '.CVE_Items[]' > nvdcve-1.1-${i}-l.json
  rm nvdcve-1.1-${i}.json
done

cat nvdcve*.json > nvd-cve-all.json
gsutil cp nvd-cve-all.json gs://cve_feeds/
bq load --replace --ignore_unknown_values --schema ../config/threatdb-schema.json --source_format=NEWLINE_DELIMITED_JSON threatdb.all gs://cve_feeds/nvd-cve-all.json
