#!/bin/bash
set -e
./mkkey1.sh
./mkkey2.sh
./mkkey3.sh
sed 's/bar/qux/' < cert-rsa-3.der > cert-rsa-3a.der
sed 's/bar/qux/; s/rsa-3/rsa-3b/g' < mkkey3.sh | bash
./mkkey4.sh
python3 mkkey4.py
for n in 1 2 3 4; do
  echo "n=$n"
  for x in cert-rsa-"$n"*.der; do
    echo "file=$x"
    j="$(java javacert.java "$x" | xxd -c0 -ps)"
    p="$(python3 canonical_name.py "$x" | xxd -c0 -ps)"
    if [ "$j" = "$p" ]; then echo OK; else echo DIFFER; fi
    if [ "$1" = -v ]; then
      java javacert.java "$x" | xxd -c32
      python3 canonical_name.py "$x" | xxd -c32
      printf '%s\n%s\n' "$j" "$p" | uniq -c
    fi
  done
done
