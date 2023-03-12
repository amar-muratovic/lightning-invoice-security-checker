# ZeeBeeGuard: Lightning Invoice Security Checker

This is a Python script that allows a user to input a Lightning invoice, generate a QR code for it, and then scan the QR code to decode the invoice. It also includes a function to check the validity of the invoice, using the pyln client library to interact with a Lightning node's RPC server.

The script first prompts the user to input the path to their lightning-rpc file. If the file path is not valid or the script is unable to connect to the RPC server, it will exit with an error message.

The check_invoice function takes in a decoded Lightning invoice and performs several checks to ensure that it is valid. These checks include verifying the payment amount, description, payment hash, payee node ID, payment preimage, and expiration time. If any of these checks fail, the function returns an error message. Additionally, if the invoice covers another invoice, the function will return an error message. If all checks pass, the function returns a message indicating that the invoice is valid.

The script then prompts the user to input the Lightning invoice they want to generate a QR code for. It uses the qrcode library to generate a QR code for the invoice and displays the resulting image. The script then prompts the user to input the path to an image file containing a QR code. It uses the zbarlight library to scan the QR code and decode the invoice.

Finally, the script calls the check_invoice function on the decoded invoice and prints the resulting message indicating whether the invoice is valid or not.

To use this Lightning invoice QR code scanner and validator script, you will need to have Python installed on your computer. You will also need to have the following Python libraries installed:

* qrcode
* pyzbar
* lnaddr
* lnrpc
* pyln.client
* nacl
* Pillow
* requests
* lndecode
 
 To install these libraries, you can use pip, which is a package manager for Python. Open a command prompt or terminal and enter the following command:

    pip install qrcode pyzbar lnaddr lnrpc pyln.client nacl Pillow requests lndecode

Once you have the necessary libraries installed, you can run the script by opening a command prompt or terminal and navigating to the directory where the script is saved. Then enter the following command:

    python lightning_invoice_qr_code.py

This will run the script and prompt you for the necessary inputs, including the path to your lightning-rpc file, the Lightning invoice you want to generate a QR code for, and the path to the image file containing the QR code.

The check_invoice function included in the script performs several checks to ensure that the Lightning invoice is valid. You can modify this function to add additional checks as needed.

Note: This script is designed to work with a Lightning node's RPC server. You will need to have access to an active Lightning node in order to use this script.

DONATION:

    Lightning network: croppednode01@walletofsatoshi.com

    BTC: bc1qk4qqspj7zqjk20y0xectd540a8wz9wgtkfqz46



