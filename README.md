# x509_canonical_name.py

Python implementation of the Java algorithm for an RFC 2253 conformant string
representation of an X.509 (X.500) distinguished name with additional
canonicalisations (as used to compare distinguished names in X.509 certificates
for equality in e.g. `apksigner` and Android).

See [the Java documentation](https://docs.oracle.com/en/java/javase/21/docs/api/java.base/javax/security/auth/x500/X500Principal.html#getName%28java.lang.String%29).

## Caveats

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
