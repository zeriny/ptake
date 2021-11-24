#!/bin/bash

#./bin/ptake_amd64 --data_path="./data/alexa100/" --result_path="./results/alexa100/" --thread=8 -check_full -check_status --module="subdomain,cname"

./bin/ptake_amd64 --dataset="alexa100" --thread=8 -check_full -check_status --module="subdomain,cname"