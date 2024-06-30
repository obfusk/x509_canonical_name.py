import binascii
import re
import sys
import unicodedata

from typing import Any, List, Tuple, Union

from asn1crypto import x509                     # type: ignore[import-untyped]


def canonical_name(name: Any) -> str:
    return ",".join("+".join(f"{t}={v}" for _, t, v in avas) for avas in comparison_name(name))


# https://docs.oracle.com/en/java/javase/11/docs/api/java.base/javax/security/auth/x500/X500Principal.html#getName(java.lang.String)
# https://android.googlesource.com/platform/libcore/+/refs/heads/android14-release/ojluni/src/main/java/sun/security/x509/RDN.java#481
# https://github.com/openjdk/jdk/blob/master/src/java.base/share/classes/sun/security/x509/RDN.java#L456
# FIXME: leading zeroes? anything else missing?
def comparison_name(name: Any, android: bool = True) -> List[List[Tuple[int, str, str]]]:
    def key(pair: Tuple[int, str, str]) -> Tuple[int, Union[str, List[int]], str]:
        o, t, v = pair
        if android and o:
            return o, [int(x) for x in t.split(".")], v
        return pair
    DS, U8, PS = x509.DirectoryString, x509.UTF8String, x509.PrintableString
    oids = {
        "2.5.4.3": ("common_name", "cn"),
        "2.5.4.6": ("country_name", "c"),
        "2.5.4.7": ("locality_name", "l"),
        "2.5.4.8": ("state_or_province_name", "st"),
        "2.5.4.9": ("street_address", "street"),
        "2.5.4.10": ("organization_name", "o"),
        "2.5.4.11": ("organizational_unit_name", "ou"),
        "0.9.2342.19200300.100.1.1": ("user_id", "uid"),
        "0.9.2342.19200300.100.1.25": ("domain_component", "dc"),
    }
    esc = {ord(c): f"\\{c}" for c in ",+<>;\"\\"}
    data = []
    for rdn in reversed(name.chosen):
        avas = []
        for type_val in rdn:
            tvt, tvv = type_val["type"], type_val["value"]
            if tvt.dotted in oids:
                o, t = 0, oids[tvt.dotted][1]   # order standard before OID
            else:
                o, t = 1, tvt.dotted
            if not (isinstance(tvv, DS) and isinstance(tvv.chosen, (U8, PS))):
                # FIXME: should use BER
                v = "#" + binascii.hexlify(tvv.dump()).decode()
            else:
                v = tvv.native or ""
                v = v.translate(esc)
                if v.startswith("#"):
                    v = "\\" + v
                v = re.sub(r" +", " ", v).strip()
                v = unicodedata.normalize("NFKD", v.upper().lower())
            avas.append((o, t, v))
        data.append(sorted(avas, key=key))
    return data


d = open(sys.argv[1], "rb").read()
c = x509.Certificate.load(d)
n = c["tbs_certificate"]["issuer"]

print(canonical_name(n))
