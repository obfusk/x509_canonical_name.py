#!/usr/bin/env python3
# encoding: utf-8
# SPDX-FileCopyrightText: 2024 FC (Fay) Stegerman <flx@obfusk.net>
# SPDX-License-Identifier: GPL-3.0-or-later

r"""
Python implementation of the Java algorithm for an RFC 2253 conformant string
representation of an X.509 (X.500) distinguished name with additional
canonicalisations (as used to compare distinguished names in X.509 certificates
for equality in e.g. `apksigner` and Android).

See the Java documentation: https://docs.oracle.com/en/java/javase/21/docs/api/java.base/javax/security/auth/x500/X500Principal.html#getName%28java.lang.String%29

Caveats
=======

NB: the Java documentation is incorrect with respect to whitespace handling.

* "Leading and trailing white space characters" means "any character whose
  codepoint is less than or equal to `U+0020` (the space character)" because
  `String.trim()` is used.  Which means it strips all ASCII control characters
  (except ESC) and doesn't strip Unicode whitespace.  NB: control characters not
  at the beginning or end are simply kept as-is.

* The "unless the value consists entirely of white space characters" part does
  not seem to be implemented.

* "Internal substrings of one or more white space characters" means `U+0020`
  (the space character) only (as even though `Character.isWhitespace()` is used,
  the only whitespace character considered printable by
  `DerValue.isPrintableStringChar()` is `U+0020`).
"""

import binascii
import re
import sys
import unicodedata

from typing import List, Tuple, Union

from asn1crypto import x509                         # type: ignore[import-untyped]


def x509_canonical_name(name: x509.Name, *,         # type: ignore[no-any-unimported]
                        android: bool = False) -> str:
    r"""
    Canonical representation of x509.Name as str (with raw control characters
    in places those are not stripped by normalisation).

    >>> name = {"common_name": " Foo  Bar", "organization_name": "My\x00Org\b"}
    >>> x509_canonical_name(x509.Name.build(name))
    'cn=foo bar,o=my\x00org'

    """
    return ",".join("+".join(f"{t}={v}" for t, v in avas)
                    for avas in x509_comparison_name(name, android=android))


def x509_friendly_name(name: x509.Name, *,          # type: ignore[no-any-unimported]
                       android: bool = False) -> str:
    r"""
    Friendly representation of x509.Name as str (with backslash escapes, no
    normalisation, canonical ordering but not canonical representation).

    >>> name = {"common_name": " Foo  Bar", "organization_name": "My\x00Org\b"}
    >>> x509_friendly_name(x509.Name.build(name))
    'CN= Foo  Bar, O=My\\x00Org\\x08'

    """
    return ", ".join("+".join(f"{t.upper()}={repr(rv)[1:-1]}" for _, t, _, rv in avas)
                     for avas in x509_ordered_name(name, android=android))


def x509_comparison_name(name: x509.Name, *,        # type: ignore[no-any-unimported]
                         android: bool = False) -> List[List[Tuple[str, str]]]:
    r"""
    Canonical representation of x509.Name as nested list.

    Returns a list of RDNs which are a list of AVAs which are a (type, value)
    tuple, where type is the standard name or dotted OID, and value is the
    normalised string representation of the value.
    """
    return [[(t, nv) for _, t, nv, _ in avas] for avas in x509_ordered_name(name, android=android)]


# FIXME: leading zeroes? anything missing?
def x509_ordered_name(name: x509.Name, *,           # type: ignore[no-any-unimported]
                      android: bool = False) -> List[List[Tuple[int, str, str, str]]]:
    r"""
    Representation of x509.Name as nested list, in canonical ordering (but also
    including non-canonical pre-normalised string values).

    Returns a list of RDNs which are a list of AVAs which are a (oid, type,
    normalised_value, raw_value) tuple, where oid is 0 for standard names and 1
    for dotted OIDs, type is the standard name or dotted OID, normalised_value
    is the normalised string representation of the value, and raw_value is the
    string value pre-normalisation.

    https://docs.oracle.com/en/java/javase/21/docs/api/java.base/javax/security/auth/x500/X500Principal.html#getName(java.lang.String)
    https://github.com/openjdk/jdk/blob/jdk-21%2B35/src/java.base/share/classes/sun/security/x509/AVA.java#L805
    https://github.com/openjdk/jdk/blob/jdk-21%2B35/src/java.base/share/classes/sun/security/x509/RDN.java#L472
    https://android.googlesource.com/platform/libcore/+/refs/heads/android14-release/ojluni/src/main/java/sun/security/x509/RDN.java#481

    '/OU=a/CN= Foo+CN=bar /OU=b/C=xx'
    >>> data = b'0A1\n0\x08\x06\x03U\x04\x0b\x0c\x01a1\x1a0\x0b\x06\x03U\x04\x03\x0c\x04 Foo0\x0b\x06\x03U\x04\x03\x0c\x04bar 1\n0\x08\x06\x03U\x04\x0b\x0c\x01b1\x0b0\t\x06\x03U\x04\x06\x13\x02xx'
    >>> name = x509.Name.load(data)
    >>> x509_canonical_name(name)
    'c=xx,ou=b,cn=bar+cn=foo,ou=a'
    >>> x509_friendly_name(name)
    'C=xx, OU=b, CN=bar +CN= Foo, OU=a'
    >>> x509_ordered_name(name)
    [[(0, 'c', 'xx', 'xx')], [(0, 'ou', 'b', 'b')], [(0, 'cn', 'bar', 'bar '), (0, 'cn', 'foo', ' Foo')], [(0, 'ou', 'a', 'a')]]

    '/custom2=42+custom1=37+O=org/emailAddress=x@y/CN= x \t\t 猫x/CN=foo  +CN=Ii   +CN=İı +CN=\u1e9eß+CN=bar  +CN=zz+CN= #,;\+\\/CN=#y'
    >>> data = b'0\x81\xbc1"0\t\x06\x03\x01\x02\x03\x0c\x02370\t\x06\x03\x01\x0b\x03\x0c\x02420\n\x06\x03U\x04\n\x0c\x03org1\x120\x10\x06\t*\x86H\x86\xf7\r\x01\t\x01\x16\x03x@y1\x130\x11\x06\x03U\x04\x03\x0c\n x \t\t \xe7\x8c\xabx1`0\t\x06\x03U\x04\x03\x0c\x02zz0\x0c\x06\x03U\x04\x03\x0c\x05Ii   0\x0c\x06\x03U\x04\x03\x0c\x05bar  0\x0c\x06\x03U\x04\x03\x0c\x05foo  0\x0c\x06\x03U\x04\x03\x0c\x05\xc4\xb0\xc4\xb1 0\x0c\x06\x03U\x04\x03\x0c\x05\xe1\xba\x9e\xc3\x9f0\r\x06\x03U\x04\x03\x0c\x06 #,;+\\1\x0b0\t\x06\x03U\x04\x03\x0c\x02#y'
    >>> name = x509.Name.load(data)
    >>> x509_canonical_name(name)
    'cn=\\#y,cn=#\\,\\;\\+\\\\+cn=bar+cn=foo+cn=ii+cn=i\u0307i+cn=zz+cn=ßss,cn=x \t\t 猫x,1.2.840.113549.1.9.1=#1603784079,o=org+0.1.11.3=#0c023432+0.1.2.3=#0c023337'
    >>> x509_friendly_name(name)
    'CN=\\\\#y, CN= #\\\\,\\\\;\\\\+\\\\\\\\+CN=bar  +CN=foo  +CN=Ii   +CN=İı +CN=zz+CN=\u1e9eß, CN= x \\t\\t 猫x, 1.2.840.113549.1.9.1=#1603784079, O=org+0.1.11.3=#0c023432+0.1.2.3=#0c023337'
    >>> x509_ordered_name(name)
    [[(0, 'cn', '\\#y', '\\#y')], [(0, 'cn', '#\\,\\;\\+\\\\', ' #\\,\\;\\+\\\\'), (0, 'cn', 'bar', 'bar  '), (0, 'cn', 'foo', 'foo  '), (0, 'cn', 'ii', 'Ii   '), (0, 'cn', 'i\u0307i', 'İı '), (0, 'cn', 'zz', 'zz'), (0, 'cn', 'ßss', '\u1e9eß')], [(0, 'cn', 'x \t\t 猫x', ' x \t\t 猫x')], [(1, '1.2.840.113549.1.9.1', '#1603784079', '#1603784079')], [(0, 'o', 'org', 'org'), (1, '0.1.11.3', '#0c023432', '#0c023432'), (1, '0.1.2.3', '#0c023337', '#0c023337')]]
    >>> x509_ordered_name(name, android=True)
    [[(0, 'cn', '\\#y', '\\#y')], [(0, 'cn', '#\\,\\;\\+\\\\', ' #\\,\\;\\+\\\\'), (0, 'cn', 'bar', 'bar  '), (0, 'cn', 'foo', 'foo  '), (0, 'cn', 'ii', 'Ii   '), (0, 'cn', 'i\u0307i', 'İı '), (0, 'cn', 'zz', 'zz'), (0, 'cn', 'ßss', '\u1e9eß')], [(0, 'cn', 'x \t\t 猫x', ' x \t\t 猫x')], [(1, '1.2.840.113549.1.9.1', '#1603784079', '#1603784079')], [(0, 'o', 'org', 'org'), (1, '0.1.2.3', '#0c023337', '#0c023337'), (1, '0.1.11.3', '#0c023432', '#0c023432')]]

    >>> control = "".join(chr(i) for i in range(32))    # no space
    >>> f = lambda cn: x509_canonical_name(x509.Name.build({"common_name": cn}))
    >>> f(f"{control}foo") == "cn=foo" == f(f"foo{control} ")
    True
    >>> f(f"\tfoo{control}bar  ")
    'cn=foo\x00\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1fbar'
    >>> f(f"  \x00 \x7f\x00foo  \x00bar 　　  ")
    'cn=\x7f\x00foo \x00bar   '

    """
    def key(ava: Tuple[int, str, str, str]) -> Tuple[int, Union[str, List[int]], str]:
        o, t, nv, _ = ava
        if android and o:
            return o, [int(x) for x in t.split(".")], nv
        return o, t, nv
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
                rv = nv = "#" + binascii.hexlify(av.dump()).decode()
            else:
                rv = (av.native or "").translate(esc)
                if rv.startswith("#"):
                    rv = "\\" + rv
                nv = unicodedata.normalize("NFKD", re.sub(r" +", " ", rv).strip(cws).upper().lower())
            avas.append((o, t, nv, rv))
        data.append(sorted(avas, key=key))
    return data


if __name__ == "__main__":
    with open(sys.argv[1], "rb") as fh:
        cert = x509.Certificate.load(fh.read())
    print(x509_canonical_name(cert["tbs_certificate"]["issuer"]))
