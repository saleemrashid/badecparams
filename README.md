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

### Extended Validation

As demonstrated in badecparams.py, it is possible to issue an EV certificate
that works in Microsoft Edge and Internet Explorer. However Chrome requires
certificate transparency logs for EV certificate issued after 2015/01/01, if CT
log is not available, the certificate still validates, but no EV indicators
will be shown.
