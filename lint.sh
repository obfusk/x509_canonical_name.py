#!/bin/bash
set -ex
shellcheck ./*.sh
flake8 ./*.py
pylint ./*.py
mypy --strict --disallow-any-unimported ./*.py
python3 -mdoctest x509_canonical_name.py
