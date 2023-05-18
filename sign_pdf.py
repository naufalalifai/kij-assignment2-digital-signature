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

# Sign a PDF file


def sign_file(input_file: str, signatureID: str, x_coordinate: int,
              y_coordinate: int, pages: Tuple = None, output_file: str = None
              ):
    if not output_file:
        output_file = (os.path.splitext(input_file)[0]) + "_signed.pdf"
    # Initialize the library
    PDFNet.Initialize(
        "demo:1684297163994:7da82d7103000000006dd30816cc050abdf7307a6c82ac748fa68c7040")
    doc = PDFDoc(input_file)
    # Create a signature field
    sigField = SignatureWidget.Create(doc, Rect(
        x_coordinate, y_coordinate, x_coordinate+100, y_coordinate+50), signatureID)
    # Iterate throughout document pages
    for page in range(1, (doc.GetPageCount() + 1)):
        if pages:
            if str(page) not in pages:
                continue
        pg = doc.GetPage(page)
        pg.AnnotPushBack(sigField)
    # Signature image
    sign_filename = os.path.dirname(
        os.path.abspath(__file__)) + "\signpdf\signature.jpg"
    # Self signed certificate
    pk_filename = os.path.dirname(
        os.path.abspath(__file__)) + "\signpdf\container.pfx"
    # Retrieve the signature field.
    approval_field = doc.GetField(signatureID)
    approval_signature_digsig_field = DigitalSignatureField(approval_field)
    # Add appearance to the signature field.
    img = Image.Create(doc.GetSDFDoc(), sign_filename)
    found_approval_signature_widget = SignatureWidget(
        approval_field.GetSDFObj())
    found_approval_signature_widget.CreateSignatureAppearance(img)
    approval_signature_digsig_field.SignOnNextSave(pk_filename, '')
    doc.Save(output_file, SDFDoc.e_incremental)
    # Develop a Process Summary
    summary = {
        "Input File": input_file, "Signature ID": signatureID,
        "Output File": output_file, "Signature File": sign_filename,
        "Certificate File": pk_filename
    }
    # Printing Summary
    print("## Summary ########################################################")
    print("\n".join("{}:{}".format(i, j) for i, j in summary.items()))
    print("###################################################################")
    return True

# sign all PDF files within a specific folder


def sign_folder(**kwargs):
    input_folder = kwargs.get('input_folder')
    signatureID = kwargs.get('signatureID')
    pages = kwargs.get('pages')
    x_coordinate = int(kwargs.get('x_coordinate'))
    y_coordinate = int(kwargs.get('y_coordinate'))
    # Run in recursive mode
    recursive = kwargs.get('recursive')
    # Loop though the files within the input folder.
    for foldername, dirs, filenames in os.walk(input_folder):
        for filename in filenames:
            # Check if pdf file
            if not filename.endswith('.pdf'):
                continue
            # PDF File found
            inp_pdf_file = os.path.join(foldername, filename)
            print("Processing file =", inp_pdf_file)
            # Compress Existing file
            sign_file(input_file=inp_pdf_file, signatureID=signatureID, x_coordinate=x_coordinate,
                      y_coordinate=y_coordinate, pages=pages, output_file=None)
        if not recursive:
            break

# Validates the path inputted and checks whether it is a file path or a folder path


def is_valid_path(path):
    if not path:
        raise ValueError(f"Invalid Path")
    if os.path.isfile(path):
        return path
    elif os.path.isdir(path):
        return path
    else:
        raise ValueError(f"Invalid Path {path}")


# Parsing command-line arguments
def parse_args():
    parser = argparse.ArgumentParser(description="Available Options")
    parser.add_argument('-l', '--load', dest='load', action="store_true",
                        help="Load the required configurations and create the certificate")
    parser.add_argument('-i', '--input_path', dest='input_path', type=is_valid_path,
                        help="Enter the path of the file or the folder to process")
    parser.add_argument('-s', '--signatureID', dest='signatureID',
                        type=str, help="Enter the ID of the signature")
    parser.add_argument('-p', '--pages', dest='pages', type=tuple,
                        help="Enter the pages to consider e.g.: [1,3]")
    parser.add_argument('-x', '--x_coordinate', dest='x_coordinate',
                        type=int, help="Enter the x coordinate.")
    parser.add_argument('-y', '--y_coordinate', dest='y_coordinate',
                        type=int, help="Enter the y coordinate.")
    path = parser.parse_known_args()[0].input_path
    if path and os.path.isfile(path):
        parser.add_argument('-o', '--output_file', dest='output_file',
                            type=str, help="Enter a valid output file")
    if path and os.path.isdir(path):
        parser.add_argument('-r', '--recursive', dest='recursive', default=False, type=lambda x: (
            str(x).lower() in ['true', '1', 'yes']), help="Process Recursively or Non-Recursively")
    args = vars(parser.parse_args())
    # To Display The Command Line Arguments
    print("## Command Arguments #################################################")
    print("\n".join("{}:{}".format(i, j) for i, j in args.items()))
    print("######################################################################")
    return args


# Main function
if __name__ == '__main__':
    # Parsing command line arguments entered by user
    args = parse_args()
    if args['load'] == True:
        load()
    else:
        # If File Path
        if os.path.isfile(args['input_path']):
            sign_file(
                input_file=args['input_path'], signatureID=args['signatureID'],
                x_coordinate=int(args['x_coordinate']), y_coordinate=int(args['y_coordinate']),
                pages=args['pages'], output_file=args['output_file']
            )
        # If Folder Path
        elif os.path.isdir(args['input_path']):
            sign_folder(
                input_folder=args['input_path'], signatureID=args['signatureID'],
                x_coordinate=int(args['x_coordinate']), y_coordinate=int(args['y_coordinate']),
                pages=args['pages'], recursive=args['recursive']
            )