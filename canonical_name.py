#!/usr/bin/env python3
# encoding: utf-8
# SPDX-FileCopyrightText: 2024 FC (Fay) Stegerman <flx@obfusk.net>
# SPDX-License-Identifier: GPL-3.0-or-later

import binascii
import re
import sys
import unicodedata

from typing import Any, List, Tuple, Union

from asn1crypto import x509                     # type: ignore[import-untyped]


def canonical_name(name: Any) -> str:
    """Canonical representation of x509.Name as str."""
    return ",".join("+".join(f"{t}={v}" for _, t, v in avas) for avas in comparison_name(name))


# FIXME: leading zeroes? anything missing?
def comparison_name(name: Any, android: bool = False) -> List[List[Tuple[int, str, str]]]:
    r"""
    Canonical representation of x509.Name as nested list.

    Returns a list of RDNs which are a list of AVAs which are a (oid, type,
    value) tuple, where oid is 0 for standard names and 1 for dotted OIDs, type
    is the standard name or dotted OID, and value is the string representation
    of the value.

    https://docs.oracle.com/en/java/javase/11/docs/api/java.base/javax/security/auth/x500/X500Principal.html#getName(java.lang.String)
    https://android.googlesource.com/platform/libcore/+/refs/heads/android14-release/ojluni/src/main/java/sun/security/x509/RDN.java#481
    https://github.com/openjdk/jdk/blob/master/src/java.base/share/classes/sun/security/x509/RDN.java#L456

    '/OU=a/CN= Foo+CN=bar /OU=b/C=xx'
    >>> data = b'0A1\n0\x08\x06\x03U\x04\x0b\x0c\x01a1\x1a0\x0b\x06\x03U\x04\x03\x0c\x04 Foo0\x0b\x06\x03U\x04\x03\x0c\x04bar 1\n0\x08\x06\x03U\x04\x0b\x0c\x01b1\x0b0\t\x06\x03U\x04\x06\x13\x02xx'
    >>> name = x509.Name.load(data)
    >>> canonical_name(name)
    'c=xx,ou=b,cn=bar+cn=foo,ou=a'
    >>> comparison_name(name)
    [[(0, 'c', 'xx')], [(0, 'ou', 'b')], [(0, 'cn', 'bar'), (0, 'cn', 'foo')], [(0, 'ou', 'a')]]

    '/custom2=42+custom1=37+O=org/emailAddress=x@y/CN= x \t\t 猫x/CN=foo  +CN=Ii   +CN=İı +CN=ẞß+CN=bar  +CN=zz+CN= #,;\+\\/CN=#y'
    >>> data = b'0\x81\xbc1"0\t\x06\x03\x01\x02\x03\x0c\x02370\t\x06\x03\x01\x0b\x03\x0c\x02420\n\x06\x03U\x04\n\x0c\x03org1\x120\x10\x06\t*\x86H\x86\xf7\r\x01\t\x01\x16\x03x@y1\x130\x11\x06\x03U\x04\x03\x0c\n x \t\t \xe7\x8c\xabx1`0\t\x06\x03U\x04\x03\x0c\x02zz0\x0c\x06\x03U\x04\x03\x0c\x05Ii   0\x0c\x06\x03U\x04\x03\x0c\x05bar  0\x0c\x06\x03U\x04\x03\x0c\x05foo  0\x0c\x06\x03U\x04\x03\x0c\x05\xc4\xb0\xc4\xb1 0\x0c\x06\x03U\x04\x03\x0c\x05\xe1\xba\x9e\xc3\x9f0\r\x06\x03U\x04\x03\x0c\x06 #,;+\\1\x0b0\t\x06\x03U\x04\x03\x0c\x02#y'
    >>> name = x509.Name.load(data)
    >>> canonical_name(name)
    'cn=\\#y,cn=#\\,\\;\\+\\\\+cn=bar+cn=foo+cn=ii+cn=i\u0307i+cn=zz+cn=ßss,cn=x \t\t 猫x,1.2.840.113549.1.9.1=#1603784079,o=org+0.1.11.3=#0c023432+0.1.2.3=#0c023337'
    >>> comparison_name(name)
    [[(0, 'cn', '\\#y')], [(0, 'cn', '#\\,\\;\\+\\\\'), (0, 'cn', 'bar'), (0, 'cn', 'foo'), (0, 'cn', 'ii'), (0, 'cn', 'i\u0307i'), (0, 'cn', 'zz'), (0, 'cn', 'ßss')], [(0, 'cn', 'x \t\t 猫x')], [(1, '1.2.840.113549.1.9.1', '#1603784079')], [(0, 'o', 'org'), (1, '0.1.11.3', '#0c023432'), (1, '0.1.2.3', '#0c023337')]]
    >>> comparison_name(name, android=True)
    [[(0, 'cn', '\\#y')], [(0, 'cn', '#\\,\\;\\+\\\\'), (0, 'cn', 'bar'), (0, 'cn', 'foo'), (0, 'cn', 'ii'), (0, 'cn', 'i\u0307i'), (0, 'cn', 'zz'), (0, 'cn', 'ßss')], [(0, 'cn', 'x \t\t 猫x')], [(1, '1.2.840.113549.1.9.1', '#1603784079')], [(0, 'o', 'org'), (1, '0.1.2.3', '#0c023337'), (1, '0.1.11.3', '#0c023432')]]

    """
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
    cws = "".join(chr(i) for i in range(32 + 1))    # control (but not esc) and whitespace
    data = []
    for rdn in reversed(name.chosen):
        avas = []
        for ava in rdn:
            at, av = ava["type"], ava["value"]
            if at.dotted in oids:
                o, t = 0, oids[at.dotted][1]        # order standard before OID
            else:
                o, t = 1, at.dotted
            if not (isinstance(av, DS) and isinstance(av.chosen, (U8, PS))):
                v = "#" + binascii.hexlify(av.dump()).decode()
            else:
                v = (av.native or "").translate(esc)
                if v.startswith("#"):
                    v = "\\" + v
                v = unicodedata.normalize("NFKD", re.sub(r" +", " ", v).strip(cws).upper().lower())
            avas.append((o, t, v))
        data.append(sorted(avas, key=key))
    return data


if __name__ == "__main__":
    with open(sys.argv[1], "rb") as fh:
        cert = x509.Certificate.load(fh.read())
    print(canonical_name(cert["tbs_certificate"]["issuer"]))
