#!/usr/bin/env bash
curl -s -LO https://www.cve-search.org/feeds/via4.json
JSON_NAME="via4.json"

sed -i 's/vuln-dev/vuln_dev/g' $JSON_NAME
sed -i 's/cert-vn/cert_vn/g' $JSON_NAME
sed -i 's/exploit-db/exploit_db/g' $JSON_NAME

pip3 install -r requirements.txt
python3 convert.py $JSON_NAME
python3 gha.py
rm $JSON_NAME
