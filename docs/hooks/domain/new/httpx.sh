#!/bin/bash
#
# BBRF hook script - /domain/new/httpx.sh
#
#  - Pass a list of domains to this script
#    to run httpx and store the urls

domains=$@

printf '%s\n' ${domains[@]} | httpx -ports 80,443,8080,8443,8000,8088 -silent -status-code -content-length -no-color | tr -d '[]' | tee \
      >(awk '{print $1" "$2" "$3}' | bbrf url add - -p @INFER);