# Import Libraries
import OpenSSL
import os
import time
import argparse
from PDFNetPython3.PDFNetPython import *
from typing import Tuple

# Creates a public/private key pair
def createKeyPair(type, bits):
    pkey = OpenSSL.crypto.PKey()
    pkey.generate_key(type, bits)
    return pkey
# Create a self signed certificate
def create_self_signed_cert(pKey):
    cert = OpenSSL.crypto.X509()
    cert.get_subject().CN = "NAUFAL ALIF"
    cert.set_serial_number(int(time.time() * 10))
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(10 * 365 * 24 * 60 * 60)
    cert.set_issuer((cert.get_subject()))
    cert.set_pubkey(pKey)
    cert.sign(pKey, 'md5')
    return cert
def load():
    summary = {}
    summary['OpenSSL Version'] = OpenSSL.__version__
    # Generating a Private Key
    key = createKeyPair(OpenSSL.crypto.TYPE_RSA, 1024)
    with open('.\signpdf\private_key.pem', 'wb') as pk:
        pk_str = OpenSSL.crypto.dump_privatekey(
            OpenSSL.crypto.FILETYPE_PEM, key)
        pk.write(pk_str)
        summary['Private Key'] = pk_str

    # Generating a self-signed client certification
    cert = create_self_signed_cert(pKey=key)
    with open('.\signpdf\certificate.cer', 'wb') as cer:
        cer_str = OpenSSL.crypto.dump_certificate(
            OpenSSL.crypto.FILETYPE_PEM, cert)
        cer.write(cer_str)
        summary['Self Signed Certificate'] = cer_str

    # Generating the public key
    with open('.\signpdf\public_key.pem', 'wb') as pub_key:
        pub_key_str = OpenSSL.crypto.dump_publickey(
            OpenSSL.crypto.FILETYPE_PEM, cert.get_pubkey())
        pub_key.write(pub_key_str)
        summary['Public Key'] = pub_key_str

    # Take a private key and a certificate and combine them into a PKCS12 file.
    # Generating a container file of the private key and the certificate
    p12 = OpenSSL.crypto.PKCS12()
    p12.set_privatekey(key)
    p12.set_certificate(cert)
    open('.\signpdf\container.pfx', 'wb').write(p12.export())

    # To Display A Summary
    print("## Initialization Summary ##################################################")
    print("\n".join("{}:{}".format(i, j) for i, j in summary.items()))
    print("############################################################################")
    return True