#!/bin/bash
set -e
openssl req -x509 -quiet -newkey rsa:2048 -sha512 -outform DER -out cert-rsa-3.der -days 10000 -nodes -utf8 -config openssl.cnf -subj '/custom2=42+custom1=37+O=org/emailAddress=x@y/CN= x '$'\t\t'' 猫x/CN=foo  +CN=Ii   +CN=İı +CN=ẞß+CN=bar  +CN=zz+CN= #,;\+\\/CN=#y' -keyout - | openssl pkcs8 -topk8 -nocrypt -outform DER -out privkey-rsa-3.der
