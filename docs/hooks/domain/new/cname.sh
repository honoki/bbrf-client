#!/bin/bash

#
# BBRF hook script - /domain/new/cname.sh
#
#  - Pass a list of domains to this script
#    to resolve CNAME records and store as a tag

domains=$@

printf '%s\n' ${domains[@]} | dnsx -silent -cname -resp | tr -d '[]' | tee \
      >(awk '{print "bbrf domain update "$1" -t cname:"$2" --append-tags"}' | bash) \
      >(awk '{print $2}' | bbrf domain add - -p @INFER);