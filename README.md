# ACME-server
Project for Network Security HS23

Public Key Infrastructures (PKIs) using X.509 certificates are used for many purposes, the most significant of which is the authentication of domain names. Certificate Authorities (CAs) are trusted to verify that an applicant for a certificate legitimately represents the domain name(s) in the certificate. Traditionally, this verification is done through various ad-hoc methods.
The Automatic Certificate Management Environment (ACME) protocol (RFC8555) aims to facilitate the automation of certificate issuance by creating a standardized and machine-friendly protocol for certificate management.

This project is an application that implements ACMEv2 and interacts with the ACME pebble server, successfully getting it to issue a certificate.


Overview of project components:

1. ACME client: An ACME client which can interact with a standard-conforming ACME server.

2. DNS server: A DNS server which resolves the DNS queries of the ACME server.

3. Challenge HTTP server: An HTTP server to respond to http-01 queries of the ACME server.

4. Certificate HTTPS server: An HTTPS server which uses a certificate obtained by the ACME client.

5. Shutdown HTTP server:  An HTTP server to receive a shutdown signal.

Application is able to use ACME to use ACME to request and obtain certificates using the dns-01 and http-01 challenge (with fresh keys in every run), request and obtain certificates which contain aliases,
request and obtain certificates with wildcard domain names, and
revoke certificates after they have been issued by the ACME server.
