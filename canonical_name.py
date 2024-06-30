import re
import sys
import unicodedata

from typing import Any

from asn1crypto import x509                     # type: ignore[import-untyped]


def canonical_name(name: Any) -> str:
    abbr = dict(                                # FIXME: incomplete
        common_name="cn",
        country_name="c",
        organizational_unit_name="ou",
    )
    esc = {ord(c): f"\\{c}" for c in ",;+"}     # FIXME: incomplete
    data = []
    for rdn in reversed(name.chosen):
        pairs = []
        for type_val in rdn:
            t = abbr.get(type_val['type'].native, type_val['type'].native)
            v = re.sub(r"\s+", " ", type_val['value'].native).strip()
            v = unicodedata.normalize("NFKD", v.translate(esc).upper().lower())
            pairs.append(f"{t}={v}")
        data.append(sorted(pairs))
    return ",".join("+".join(pairs) for pairs in data)


d = open(sys.argv[1], "rb").read()
c = x509.Certificate.load(d)
n = c["tbs_certificate"]["issuer"]

print(canonical_name(n))
