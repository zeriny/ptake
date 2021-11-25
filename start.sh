#!/bin/bash

#./bin/ptake_amd64 --data_path="./data/alexa100/" --result_path="./results/alexa100/" --thread=8 -check_full -check_status --module="subdomain,cname"

# Aliyun Cloud VPS
dataset="alexa1k"
# ./bin/ptake_amd64 --dataset=${dataset} --thread=8 -check_full -check_status --module="subdomain" -v
python utils/filterRandomString.py data/${dataset}/fqdn.txt data/${dataset}/fqdn_filtered.txt
mv data/${dataset}/fqdn.txt data/${dataset}/fqdn_raw.txt
mv data/${dataset}/fqdn_filtered.txt data/${dataset}/fqdn.txt

./bin/ptake_amd64 --dataset=${dataset} --thread=8 -check_full -check_status --module="cname" -v
python utils/filterRandomString.py data/${dataset}/cname.txt data/${dataset}/cname_filtered.txt
mv data/${dataset}/cname.txt data/${dataset}/cname_raw.txt
mv data/${dataset}/cname_filtered.txt data/${dataset}/cname.txt

# ./bin/ptake_amd64 --dataset=${dataset} --thread=8 -check_full -check_status --module="check" -v
