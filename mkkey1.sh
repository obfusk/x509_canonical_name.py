#!/bin/bash
openssl req -x509 -quiet -newkey rsa:2048 -sha512 -outform DER -out cert-rsa-1.der -days 10000 -nodes -subj '/OU=a/CN= Foo+CN=bar /OU=b/C=xx' -keyout - | openssl pkcs8 -topk8 -nocrypt -outform DER -out privkey-rsa-1.der
