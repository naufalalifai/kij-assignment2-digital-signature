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