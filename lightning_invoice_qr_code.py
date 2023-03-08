import io
import os
import qrcode
import requests
from PIL import Image
from pyln.client import LightningRpc
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


def check_payment_details(invoice, rpc):
    try:
        payment_details = rpc.decodepay(invoice)
    except ValueError:
        return "Invalid Lightning invoice"

    try:
        amount = payment_details['msatoshi'] / Constants.PAYMENT_FACTOR
    except KeyError:
        return "Invalid payment details: amount"

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
