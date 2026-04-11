# BADECPARAMS

Proof of Concept for CVE-2026-5194.

[badecparams.py](badecparams.py) generates an intermediate certificate
authority that exploits the vulnerability, then issues TLS certificates.

[httpd.py](httpd.py) serves the contents of the [www](www) subfolder over
HTTPS, using the PEM encoded certificate chain provided on the command line.

```shell
./badecparams.py
./httpd.py localhost.key
```
