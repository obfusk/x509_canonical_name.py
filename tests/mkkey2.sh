#!/bin/bash
set -e
openssl req -x509 -quiet -newkey rsa:2048 -sha512 -outform DER -out cert-rsa-2.der -days 10000 -nodes -subj '/C=xx/CN=bar+CN=foo/OU=b/OU=a' -keyout - | openssl pkcs8 -topk8 -nocrypt -outform DER -out privkey-rsa-2.der
