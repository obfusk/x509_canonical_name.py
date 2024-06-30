import re
import sys
import unicodedata

from typing import Any

from asn1crypto import x509                 # type: ignore[import-untyped]


def canonical_name(name: Any) -> str:
    abbr = dict(                            # FIXME: incomplete
        common_name="cn",
        country_name="c",
        organizational_unit_name="ou",
    )
    esc = {ord(c): f"\\{c}" for c in ",;"}  # FIXME: incomplete
    data = []
    for rdn in reversed(name.chosen):
        x = []
        for type_val in rdn:
            t = abbr.get(type_val['type'].native, type_val['type'].human_friendly.lower())
            v = type_val['value'].native
            if not v.isspace():
                v = re.sub(r"\s+", " ", v).strip()
            v = unicodedata.normalize("NFKD", v.translate(esc).upper().lower())
            x.append(f"{t}={v}")
        data.append(sorted(x))
    return ",".join("+".join(x) for x in data)


d = open(sys.argv[1], "rb").read()
c = x509.Certificate.load(d)
n = c["tbs_certificate"]["issuer"]

# print(n.native)
# print(n.human_friendly)
# print(unicodedata.normalize("NFKD", n.human_friendly.upper().lower()))

print(canonical_name(n))
