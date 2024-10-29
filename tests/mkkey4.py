for n in "abcdef":
    f, f0 = f"cert-rsa-4{n}.der", f"cert-rsa-4{n}0.der"
    with open(f, "rb") as fhi:
        with open(f0, "wb") as fho:
            fho.write(fhi.read().replace(b"\a", b"\x00").replace(b"\xc2\x88", b"\x00\x00"))
