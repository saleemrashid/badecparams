# BADECPARAMS

Proof of Concept for CVE-2020-0601.

![](screenshot.png)

`badecparams.py` generates a root certificate authority that exploits the
vulnerability, then issues Authenticode and TLS certificates. The TLS
certificates have Extended Validation in Microsoft Edge or Internet Explorer.

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

Chrome 79.0.3945.130 returns `NET::ERR_CERT_INVALID`, even on machines that
haven't been patched.
