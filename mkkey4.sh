#!/bin/bash
set -e
control1="$(python3 control1.py)"
control2="$(python3 control2.py)"
subjs1=( "/CN=${control1}foo" "/CN=foo${control1}" "/CN=foo${control1}bar" )
subjs2=( "/CN=${control2}foo" "/CN=foo${control2}" "/CN=foo${control2}bar" )
numbs1=( a b c )
numbs2=( d e f )
genkey() {
  local s="$1" n="$2"
  openssl req -x509 -quiet -newkey rsa:2048 -sha512 -outform DER -out "cert-rsa-4$n.der" -days 10000 -nodes -utf8 -config openssl.cnf -subj "$s" -keyout - | openssl pkcs8 -topk8 -nocrypt -outform DER -out "privkey-rsa-4$n.der"
}
for i in 0 1 2; do
  genkey "${subjs1[i]}" "${numbs1[i]}"
  genkey "${subjs2[i]}" "${numbs2[i]}"
done
