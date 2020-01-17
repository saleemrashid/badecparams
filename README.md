# BADECPARAMS

Proof of Concept for CVE-2020-0601.

`badecparams.py` generates a root certificate authority that exploits the
vulnerability, then issues Authenticode and TLS certificates.

`httpd.py` serves the contents of the `www` subfolder with the TLS certificate
chain provided on the command line.

### Vulnerable Software

Windows Update is not vulnerable because it uses public key pinning and RSA
keys.

The latest Windows Defender antivirus definitions detect executables signed
with malicious Authenticode certificates, even on machines that haven't
been patched.

Microsoft Edge, Internet Explorer, and Chrome (and derivatives) are vulnerable
to the TLS variant. Firefox is not vulnerable because Mozilla's Network
Security Services (NSS) does not support explicit EC parameters and uses its
own implementation for certificate verification.

The root certificate authority needs to be cached in order for the
vulnerability to occur. For example, the "GlobalSign ECC Root CA - R5"
certificate used by `badecparams.py` can be cached by accessing a legitimate
website using this certificate authority, such as https://www.bbc.co.uk.

### Extended Validation

While it is possible to issue an EV certificate that works in Microsoft Edge,
it will cause Chrome to throw `NET::ERR_CERT_AUTHORITY_INVALID`. This is
because Chrome checks the root certificate of EV certificates against a
hardcoded list, and will detect that the SHA-256 fingerprint of our modified
certificate does not match.
