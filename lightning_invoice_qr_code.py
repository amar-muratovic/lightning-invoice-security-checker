import io
import os
import time
import qrcode
import requests
import hashlib
import base64
import argparse
import nacl.signing
import json
import csv
import requests
import lnaddr
import lnd_grpc.lnrpc as lnrpc
from io import BytesIO
from PIL import Image
from pyln.client import LightningRpc
from datetime import datetime, timedelta
import pyzbar.pyzbar as pyzbar


class InvalidFileError(Exception):
    pass


class RpcConnectionError(Exception):
    pass


def prompt_for_rpc_path():
    parser = argparse.ArgumentParser(
        description='Enter path to your lightning-rpc')
    parser.add_argument('rpc_path', type=str,
                        help='path to your lightning-rpc file')

    args = parser.parse_args()

    rpc_path = args.rpc_path

    if not os.path.isfile(rpc_path):
        print("Error: File path is not valid")
    else:
        try:
            rpc = LightningRpc(rpc_path, ssl=True)
            return rpc
        except RpcConnectionError:
            print("Error: Unable to connect to RPC server")


def generate_qr_code(invoice):
    if not invoice.startswith(("lightning:", "lnbc:")):
        invoice = "lightning:" + invoice
    qr = qrcode.QRCode(
        version=1, error_correction=qrcode.constants.ERROR_CORRECT_L, box_size=10, border=4)
    qr.add_data(invoice)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    return img


def display_qr_code(img):
    img.show()


def save_qr_code(img, file_path):
    img.save(file_path)


def decode_qr_codes(img_paths):
    invoices = []
    for img_path in img_paths:
        with open(img_path, 'rb') as image_file:
            image = Image.open(io.BytesIO(image_file.read()))
            image.load()

        codes = pyzbar.decode(image)
        if not codes:
            raise ValueError("No QR code found in the image")

        invoice = codes[0].data.decode('utf-8')
        try:
            decoded_invoice = lnaddr.decode(invoice)
            payment_hash = decoded_invoice.payment_hash.hex()
            payment_preimage = decoded_invoice.payment_preimage.hex()
            invoices.append(decoded_invoice)
        except lnaddr.exceptions.UnexpectedPrefix as e:
            raise ValueError(f"Invalid Lightning invoice: {e}")

    return invoices, payment_hash, payment_preimage


def generate_qr_code(invoice, file_name=None):
    if not invoice.startswith(("lightning:", "lnbc:")):
        invoice = "lightning:" + invoice
    qr = qrcode.QRCode(
        version=1, error_correction=qrcode.constants.ERROR_CORRECT_L, box_size=10, border=4)
    qr.add_data(invoice)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    if file_name:
        img.save(file_name)
    buffer = BytesIO()
    img.save(buffer, format='PNG')
    qr_code_data = base64.b64encode(buffer.getvalue()).decode('utf-8')
    return qr_code_data


def scan_qr_code():
    try:
        from PIL import ImageGrab
    except ImportError:
        print(
            "Error: Pillow library not found. Please install it with 'pip install pillow'")
        quit()

    parser = argparse.ArgumentParser(
        description='Scan a QR code from the screen')
    parser.add_argument('--position', default=False, action='store_true',
                        help='Show a rectangle to select the position of the QR code on the screen')
    args = parser.parse_args()

    if args.position:
        print("Please position your QR code on the screen")
        input("Press Enter to capture screen...")

    screen = ImageGrab.grab()
    screen.show()

    # Convert image to grayscale for barcode detection
    screen = screen.convert('L')
    codes = pyzbar.decode(screen)

    if not codes:
        raise ValueError("No QR code found in the screen capture")

    invoice = codes[0].data.decode('utf-8')
    return invoice


def get_node_info(node_id):
    url = f"https://1ml.com/node/{node_id}/json"
    response = requests.get(url)
    if response.status_code != 200:
        raise ValueError(
            f"Error retrieving node information: {response.status_code}")
    data = response.json()
    return {
        'alias': data.get('alias'),
        'public_key': data.get('public_key'),
        'num_channels': data.get('num_channels'),
        'total_capacity': data.get('total_capacity'),
        'channels': [
            {
                'id': channel['short_channel_id'],
                'capacity': channel['satoshis'],
                'public_key': channel['node1_pub'] if channel['node1_pub'] != data['public_key'] else channel['node2_pub'],
                'active': channel['active']
            }
            for channel in data.get('channels', [])
        ]
    }


class Constants:
    MAX_PAYMENT_AMOUNT = 100000000  # 1 BTC in satoshis


def check_payment_details(invoice, rpc):
    if not invoice.startswith("lightning:") and not invoice.startswith("lnbc:"):
        invoice = "lightning:" + invoice

    try:
        payment_details = rpc.decodepay(invoice)
    except ValueError:
        return "Invalid Lightning invoice"

    try:
        amount = int(payment_details['msatoshi'])
        if amount <= 0 or amount > Constants.MAX_PAYMENT_AMOUNT:
            raise ValueError("Invalid payment amount")
    except KeyError:
        return "Invalid payment details: amount"
    except ValueError as e:
        return "Invalid payment amount: " + str(e)

    try:
        description = payment_details['description']
        if "hack" in description.lower() or "malicious" in description.lower():
            raise ValueError("Malicious invoice description")
    except KeyError:
        return "Invalid payment details: description"

    try:
        payment_hash = payment_details['payment_hash']
        decoded = rpc.decodepay(payment_details['bolt11'])
        if decoded['payment_hash'] != payment_hash:
            raise ValueError("Invalid payment hash")
        if decoded['description_hash'] is not None:
            raise ValueError("Invoice covers another invoice")
        expiry = decoded['expiry']
        if expiry <= 0:
            raise ValueError("Invoice has expired")
        elif expiry < 60:
            raise ValueError("Expiration time is too short")
        elif expiry > 3600:
            raise ValueError("Expiration time is too long")
        payment_preimage = decoded['payment_preimage']
        if not payment_preimage:
            raise ValueError("Invalid payment preimage")

        # check metadata
        metadata = decoded.get('metadata', {})
        routing_info = metadata.get('routing', [])
        for route in routing_info:
            if len(route['pubkey']) != 66:
                raise ValueError("Invalid routing pubkey")

        # check timestamp
        timestamp = decoded.get('timestamp')
        if timestamp is not None:
            current_time = int(time.time())
            if timestamp > current_time + 3600 or timestamp < current_time - 3600:
                raise ValueError("Invalid timestamp")
    except KeyError:
        return "Invalid payment details"
    except ValueError as e:
        return "Invalid payment details: " + str(e)

    return "Payment details are valid"


def is_invoice_expired(invoice, expiry_time):
    """
    Checks if the invoice has expired given an expiry time.
    
    Parameters:
    invoice (dict): A dictionary representing an invoice with keys "expiry_time" and "amount".
    expiry_time (datetime): The expiry time for the invoice.
    
    Returns:
    bool: True if the invoice has expired, False otherwise.
    """
    now = datetime.utcnow()
    invoice_expiry_time = datetime.fromisoformat(invoice["expiry_time"])

    if now > expiry_time or invoice_expiry_time > expiry_time:
        return True

    return False


def verify_invoice_signature(invoice, pubkey):
    """
    Verify that the invoice has been signed by the given public key.

    Args:
        invoice (str): The invoice to verify.
        pubkey (str): The public key to verify the signature against.

    Returns:
        bool: True if the signature is valid, False otherwise.
    """

    # Split the invoice into its parts
    signature_b64, message_b64 = invoice.split(":", 1)

    # Decode the signature and message from base64
    signature = base64.b64decode(signature_b64)
    message = base64.b64decode(message_b64)

    # Hash the message
    message_hash = hashlib.sha256(message).digest()

    # Verify the signature using the given public key
    try:
        verifying_key = nacl.signing.VerifyKey(
            pubkey, encoder=nacl.encoding.HexEncoder)
        verifying_key.verify(message_hash, signature)
        return True
    except:
        return False


def validate_invoice(invoice, recipient, expected_amount, expected_description, expected_hash, expected_expiry, expected_secret=None, expected_description_hash=None):
    if not invoice:
        return False

    # Check if payee node ID matches the intended recipient
    if invoice.get('payee') != recipient:
        return False

    # Check if invoice has routing hints or fallback addresses
    if invoice.get('routing_info') is None or invoice.get('fallback_addr') is None:
        return False

    # Check if invoice has an amount field and if it matches the expected payment amount
    if invoice.get('num_satoshis') != expected_amount:
        return False

    # Check if invoice has an expiration time and if it has not yet expired
    if invoice.get('expiry') < time.time():
        return False

    # Check if invoice has a description field and if it matches the expected payment description
    if invoice.get('description') != expected_description:
        return False

    # Check if invoice has a payment hash field and if it matches the expected payment hash
    if invoice.get('payment_hash') != expected_hash:
        return False

    # Check if invoice has a min_final_cltv_expiry field and if it is not lower than the expected value
    if invoice.get('min_final_cltv_expiry') < expected_expiry:
        return False

    # Check if invoice has a description_hash field and if it matches the expected payment description hash
    if expected_description_hash and invoice.get('description_hash') != expected_description_hash:
        return False

    # Check if invoice has a payment_secret field and if it matches the expected payment secret (if provided)
    if expected_secret and invoice.get('payment_secret') != expected_secret:
        return False

    # All checks passed, invoice is valid
    return True


def validate_invoice_signature(invoice, rpc):
    """
    Validates the authenticity of a lightning invoice by checking its signature.

    Args:
        invoice (str): The lightning invoice to validate.
        rpc (LightningRpc): The LightningRpc object used to communicate with LND.

    Returns:
        bool: True if the invoice signature is valid, False otherwise.
    """
    if not invoice.startswith("lightning:") and not invoice.startswith("lnbc:"):
        invoice = "lightning:" + invoice

    try:
        payment_request = rpc.decodepay(invoice)
    except ValueError:
        raise ValueError("Invalid Lightning invoice")

    if 'signature' not in payment_request:
        raise ValueError("Payment request does not contain a signature")

    pubkey = base64.b64decode(payment_request['payee'])
    sig = base64.b64decode(payment_request['signature'])
    data = invoice.encode('utf-8')
    verify_key = nacl.signing.VerifyKey(
        pubkey, encoder=nacl.encoding.Base64Encoder())
    try:
        verify_key.verify(data, sig)
    except nacl.exceptions.BadSignatureError:
        return False

    return True


class Invoice:
    def __init__(self, amount):
        self.amount = amount
        self.status = "unpaid"
        self.payment_attempts = 0

    def pay(self, payment_amount):
        if self.status == "paid":
            print("Invoice already paid.")
        elif payment_amount == self.amount:
            self.status = "paid"
            self.payment_attempts += 1
            print("Invoice paid successfully.")
        else:
            print("Payment amount does not match invoice amount.")

    def check_payment_attempts(self):
        if self.payment_attempts >= 2:
            print("Multiple payment attempts detected. Please contact customer support.")


def main(output_format, output_stream):
    try:
        rpc = prompt_for_rpc_path()
    except InvalidFileError:
        return

    while True:
        user_input = input("Enter Lightning invoice or QR code file path: ")
        if os.environ.get('QR_FILE_PATH') and user_input == "":
            img_path = os.environ['QR_FILE_PATH']
            try:
                invoices = decode_qr_codes([img_path])
                invoice = invoices[0]
            except ValueError as e:
                print("Error:", e)
                continue
        elif user_input.startswith("ln"):
            invoice = user_input
        else:
            print("Error: Invalid input")
            continue

        if os.environ.get('SCAN_QR_CODE') and not os.environ.get('QR_FILE_PATH'):
            qr_data = scan_qr_code()
            if qr_data:
                try:
                    invoices = decode_qr_codes([io.BytesIO(qr_data)])
                    invoice = invoices[0]
                except ValueError as e:
                    print("Error:", e)
                    continue
            else:
                continue

        img_path = input(
            "Enter file path to save QR code image (leave empty to skip): ")
        if img_path:
            img = generate_qr_code(invoice)
            save_qr_code(img, img_path)

        validation_result = check_payment_details(invoice, rpc)

        if output_format == 'json':
            json.dump(validation_result, output_stream)
            output_stream.write('\n')
        elif output_format == 'csv':
            csv_output = csv.writer(output_stream)
            for k, v in validation_result.items():
                csv_output.writerow([k, v])
        else:
            print(validation_result)

        break
