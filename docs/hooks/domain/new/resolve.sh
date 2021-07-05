#!/bin/bash

#
# BBRF hook script - /domain/new/resolve.sh
#
#  - Pass a list of domains to this script
#    to resolve and update the domain
#    and to store the IPs as well

domains=$@

printf '%s\n' ${domains[@]} | dnsx -silent -a -resp | tr -d '[]' | tee \
      >(awk '{print $1":"$2}' | bbrf domain update -) \
      >(awk '{print $2":"$1}' | bbrf ip add - -p @INFER) \
      >(awk '{print $2":"$1}' | bbrf ip update -);