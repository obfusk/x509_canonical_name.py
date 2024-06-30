#!/bin/bash
./mkkey1.sh
./mkkey2.sh
./mkkey3.sh
sed 's/bar/qux/' < cert-rsa-3.der > cert-rsa-3a.der
sed 's/bar/qux/; s/rsa-3/rsa-3b/g' < mkkey3.sh | bash
for x in cert-rsa-*.der; do
  java javacert.java "$x"
  python3 canonical_name.py "$x"
done | tr '\t' 'T' | uniq -c
