# PKI examples

During my bachelor study at TU Darmstadt, I had a course about Public Key Infrastructure. This repository contains part of the practical
exercises I did for that course and is ment for educational purposes only.

RSA based:
- key extractions from POM files
- encrypt, sign and verify
- X509 certificate creation and verification

Hybrid crypto based on RSA and QTESLA keys:
- X509 certificate chain verification
- PKCS10CertificationRequest creation
- CA certificate creation for open PKCS10CertificationRequest
- End Entity certificate creation

The code is written in Kotlin and uses custom BouncyCastle libraries, which are included in `/libs` and were copied from:
https://github.com/CROSSINGTUD/bc-hybrid-certificates

Generated certificates can manually be inspected with the [openssl](https://www.openssl.org/) CLI utility: `openssl x509 -in certificate.crt -text -noout`