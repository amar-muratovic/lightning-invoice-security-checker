import io
import os
import time
import qrcode
import requests
import hashlib
import base64
import nacl.signing
from PIL import Image
from pyln.client import LightningRpc
from datetime import datetime, timedelta
import pyzbar.pyzbar as pyzbar


class InvalidFileError(Exception):
    pass


class RpcConnectionError(Exception):
    pass


def prompt_for_rpc_path():
    while True:
        rpc_path = input("Enter path to your lightning-rpc: ")
        if not os.path.isfile(rpc_path):
            print("Error: File path is not valid")
        else:
            try:
                rpc = LightningRpc(rpc_path, ssl=True)
                return rpc
            except RpcConnectionError:
                print("Error: Unable to connect to RPC server")


def generate_and_save_qr_code(invoice, img_path):
    qr = qrcode.QRCode(
        version=1, error_correction=qrcode.constants.ERROR_CORRECT_L, box_size=10, border=4)
    qr.add_data(invoice)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    img.save(img_path)
    print("QR code image saved to:", img_path)


def decode_qr_code(img_path):
    with open(img_path, 'rb') as image_file:
        image = Image.open(io.BytesIO(image_file.read()))
        image.load()

    codes = pyzbar.decode(image)
    if not codes:
        raise ValueError("No QR code found in the image")

    invoice = codes[0].data.decode('utf-8')

    return invoice


def scan_qr_code():
    try:
        from PIL import ImageGrab
    except ImportError:
        print(
            "Error: Pillow library not found. Please install it with 'pip install pillow'")
        return

    print("Please position your QR code on the screen")

    # Allow user to select a region on the screen
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


class Constants:
    PAYMENT_FACTOR = 1000
    MAX_PAYMENT_AMOUNT = 100000000  # 1 BTC in satoshis


def check_payment_details(invoice, rpc):
    try:
        payment_details = rpc.decodepay(invoice)
    except ValueError:
        return "Invalid Lightning invoice"

    try:
        amount = payment_details['msatoshi'] / Constants.PAYMENT_FACTOR
    except KeyError:
        return "Invalid payment details: amount"

    if amount <= 0:
        return "Invalid payment amount"
    if amount > Constants.MAX_PAYMENT_AMOUNT / Constants.PAYMENT_FACTOR:
        return "Payment amount exceeds the maximum allowed amount"

    try:
        description = payment_details['description']
    except KeyError:
        return "Invalid payment details: description"

    try:
        payment_hash = payment_details['payment_hash']
    except KeyError:
        return "Invalid payment details: payment_hash"

    try:
        payee_node_id = payment_details['payee_node_id']
    except KeyError:
        return "Invalid payment details: payee_node_id"

    if amount <= 0:
        return "Invalid payment amount"
    if "hack" in description.lower() or "malicious" in description.lower():
        return "Malicious invoice description"

    try:
        decoded = rpc.decodepay(payment_details['bolt11'])
    except ValueError:
        return "Invalid payment details: bolt11"

    if decoded['payment_hash'] != payment_hash:
        return "Invalid payment hash"

    with requests.Session() as session:
        r = session.get("https://1ml.com/node/" + payee_node_id)
        if r.status_code != 200:
            return "Invalid payee node ID"

    try:
        payment_status = rpc.listinvoices(
            payment_hash)['invoices'][0]['status']
    except (IndexError, KeyError):
        return "Invalid payment details: payment_status"

    if payment_status != 'unpaid':
        return "Invoice has already been paid"

    try:
        expiry = decoded['expiry']
    except KeyError:
        return "Invalid payment details: expiry"

    if expiry <= 0:
        return "Invoice has expired"

    try:
        payment_preimage = decoded['payment_preimage']
    except KeyError:
        return "Invalid payment details: payment_preimage"

    if not payment_preimage:
        return "Invalid payment preimage"

    if decoded['description_hash'] is not None:
        return "Invoice covers another invoice"

    return "Invoice is valid"


def is_invoice_expired(invoice, min_expiry_time=timedelta(minutes=5), max_expiry_time=timedelta(days=30)):
    """
    Checks if the invoice has expired and if the expiry time is reasonable.
    
    Parameters:
    invoice (dict): A dictionary representing an invoice with keys "expiry_time" and "amount".
    min_expiry_time (timedelta): The minimum acceptable expiry time.
    max_expiry_time (timedelta): The maximum acceptable expiry time.
    
    Returns:
    bool: True if the invoice has expired or the expiry time is not reasonable, False otherwise.
    """
    now = datetime.utcnow()
    expiry_time = datetime.fromisoformat(invoice["expiry_time"])

    if now > expiry_time:
        return True

    if expiry_time - now < min_expiry_time or expiry_time - now > max_expiry_time:
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


def main():
    try:
        rpc = prompt_for_rpc_path()
    except InvalidFileError:
        return

    while True:
        user_input = input("Enter Lightning invoice or QR code file path: ")
        if os.environ.get('QR_FILE_PATH') and user_input == "":
            img_path = os.environ['QR_FILE_PATH']
            try:
                invoice = decode_qr_code(img_path)
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
                    invoice = decode_qr_code(io.BytesIO(qr_data))
                except ValueError as e:
                    print("Error:", e)
                    continue
            else:
                continue

        img_path = input(
            "Enter file path to save QR code image (leave empty to skip): ")
        if img_path:
            generate_and_save_qr_code(invoice, img_path)

        validation_result = check_payment_details(invoice, rpc)
        print(validation_result)
        break
