import sys
#https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption/
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
#https://cryptography.io/en/latest/hazmat/primitives/padding/
from cryptography.hazmat.primitives import padding
import argparse
import binascii

def read_file_in_bytes(file_path):
    try:
        with open(file_path, 'rb') as file:
            return file.read()
    except:
        return None

def write_file_in_bytes(file_path, data):
    try:
        with open(file_path, 'wb') as file:
            file.write(data)
    except:
        return None

if len(sys.argv) < 5:
    exit(1)

parser = argparse.ArgumentParser(description='AES Encryption Script')
parser.add_argument('-key')
parser.add_argument('-IV')
parser.add_argument('-mode')
parser.add_argument('-input', dest='in_filename')
parser.add_argument('-out')
parser.add_argument('-gcm_arg')

args = parser.parse_args()

key = args.key
iv = args.IV
mode = args.mode
in_filename = args.in_filename
out_filename = args.out
gcm_arg_file = args.gcm_arg
gcm_arg = None
tag = None

if mode not in ["ecb", "cbc", "gcm"]:
    exit(1)

if mode == "cbc" and iv is None:
    exit(1)

if mode == "gcm" and (iv is None and gcm_arg is None):
    exit(1)

key_data = read_file_in_bytes(key)
key = binascii.unhexlify(key_data)

if iv is not None:
    iv_data = read_file_in_bytes(iv)
    iv = binascii.unhexlify(iv_data)

in_data = read_file_in_bytes(in_filename)

if gcm_arg_file is not None:
    gcm_arg = read_file_in_bytes(gcm_arg_file)

#decrypt
cipher = None
encrypted_data = None
tag = None

if mode == "ecb":
    cipher = Cipher(algorithms.AES(key), modes.ECB())
elif mode == "cbc":
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
elif mode == "gcm":
    tag = in_data[-16:]
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag))

decryptor = cipher.decryptor()


if mode in ["ecb", "cbc"]:
    decrypted_data = decryptor.update(in_data) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()
    write_file_in_bytes(out_filename, unpadded_data)

elif mode == "gcm":
    encrypted_data = in_data[:-16]
    decryptor.authenticate_additional_data(gcm_arg)
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
    write_file_in_bytes(out_filename, decrypted_data)
