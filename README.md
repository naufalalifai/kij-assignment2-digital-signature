# kij-assignment2-digital-signature

## Group Members :

1. 05111940000192 - Andymas Narendra Bagaskara
2. 05111942000003 - Ahmad Zaki Azhari
3. 05111942000008 - Muhammad Naufal Alif Islami

## How to Run

1. pip install PDFNetPython3 pyOpenSSL
2. python sign_pdf.py --help 
    - see the available command-line arguments to pass
3. python sign_pdf.py --load
    - generate a self-signed certificate using  public/private key pair
4. python sign_pdf.py -i ".\signpdf\Restaurant Employment Confirmation Letter.pdf" -s "BM" -x 60 -y 370
    - sign the pdf
