#!/bin/bash

#
# BBRF hook script - /ip/new/add-tags.sh
#

ips=$@
providers=( "cloudflare" "akamai" )

for p in ${providers[@]}; do
 comm -12 /root/wordlists/cdn/$p.txt <(printf '%s\n' ${ips[@]} | sort) | bbrf ip update - -t cdn:$p;
done