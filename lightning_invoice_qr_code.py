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


def check_payment_details(invoice, rpc):
    try:
        payment_details = rpc.decodepay(invoice)
    except:
        return "Invalid Lightning invoice"

    amount = payment_details['msatoshi'] / 1000
    description = payment_details['description']
    payment_hash = payment_details['payment_hash']
    payee_node_id = payment_details['payee_node_id']

    if amount <= 0:
        return "Invalid payment amount"
    if "hack" in description.lower() or "malicious" in description.lower():
        return "Malicious invoice description"

    decoded = rpc.decodepay(payment_details['bolt11'])
    if decoded['payment_hash'] != payment_hash:
        return "Invalid payment hash"

    with requests.Session() as session:
        r = session.get("https://1ml.com/node/" + payee_node_id)
        if r.status_code != 200:
            return "Invalid payee node ID"

    payment_status = rpc.listinvoices(payment_hash)['invoices'][0]['status']
    if payment_status != 'unpaid':
        return "Invoice has already been paid"

    expiry = decoded['expiry']
    if expiry <= 0:
        return "Invoice has expired"

    if not decoded['payment_preimage']:
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
        invoice = input("Enter Lightning invoice: ")
        if not invoice.startswith("ln"):
            print("Error: Invalid Lightning invoice")
            continue

        img_path = input("Enter file path to save QR code image: ")
        generate_and_save_qr_code(invoice, img_path)

        try:
            invoice = decode_qr_code(img_path)
        except ValueError as e:
            print("Error:", e)
            continue

        validation_result = check_payment_details(invoice, rpc)
        print(validation_result)
        break
