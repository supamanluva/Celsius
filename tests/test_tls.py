"""Offline tests for TLS certificate decoding and validation-failure recovery.
Stdlib-only: run directly (`python tests/test_tls.py`) or under pytest.
"""
from __future__ import annotations

import os
import ssl
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from celsius.recon import tls  # noqa: E402


class _Socket:
    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def getpeercert(self, binary_form=False):
        return b"certificate-der" if binary_form else {}

    def version(self):
        return "TLSv1.3"

    def cipher(self):
        return ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)


def test_decode_certificate_rejects_malformed_der():
    assert tls._decode_certificate(b"not-a-certificate") == {}
    assert tls._decode_certificate(b"") == {}


def test_analyze_recovers_san_after_hostname_mismatch():
    real_connect = tls._connect
    real_probe = tls._probe_legacy
    real_decode = tls._decode_certificate
    decoded = []
    cert = {
        "subject": ((("commonName", "example.com"),),),
        "issuer": ((("commonName", "Example CA"),),),
        "subjectAltName": (("DNS", "example.com"), ("DNS", "www.example.com")),
    }

    def fake_connect(host, port, context):
        if context.verify_mode == ssl.CERT_REQUIRED:
            raise ssl.SSLCertVerificationError("IP address mismatch")
        return _Socket()

    def fake_decode(der):
        decoded.append(der)
        return cert

    try:
        tls._connect = fake_connect
        tls._probe_legacy = lambda host, port: []
        tls._decode_certificate = fake_decode
        info, findings, errors = tls.analyze("192.0.2.10")
    finally:
        tls._connect = real_connect
        tls._probe_legacy = real_probe
        tls._decode_certificate = real_decode

    assert decoded == [b"certificate-der"]
    assert info["verified"] is False
    assert info["san"] == ["example.com", "www.example.com"]
    assert info["subject"] == "example.com"
    assert info["issuer"] == "Example CA"
    assert errors == []
    assert [f.title for f in findings] == ["TLS certificate hostname mismatch"]


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    failed = 0
    for fn in fns:
        try:
            fn()
            print(f"PASS {fn.__name__}")
        except AssertionError as e:
            failed += 1
            print(f"FAIL {fn.__name__}: {e}")
    print(f"\n{len(fns) - failed}/{len(fns)} passed")
    sys.exit(1 if failed else 0)
