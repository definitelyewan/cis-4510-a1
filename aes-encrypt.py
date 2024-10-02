import sys
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
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
parser.add_argument('-input')
parser.add_argument('-out')
parser.add_argument('-gcm_arg')

args = parser.parse_args()

key = args.key
iv = args.IV
mode = args.mode
in_filename = args.input
out_filename = args.out
gcm_arg_file = args.gcm_arg
gcm_arg = None

if mode not in ["ecb", "cbc", "gcm"]:
    exit(1)

if mode == "cbc" and iv is None:
    exit(1)

if mode == "gcm" and (iv is None or gcm_arg_file is None):
    exit(1)

key_data = read_file_in_bytes(key)
key = binascii.unhexlify(key_data)

if iv is not None:
    iv_data = read_file_in_bytes(iv)
    iv = binascii.unhexlify(iv_data)

in_data = read_file_in_bytes(in_filename)

if gcm_arg_file is not None:
    gcm_arg = read_file_in_bytes(gcm_arg_file)

# Encrypt
cipher = None
encrypted_data = None
tag = None

if mode == "ecb":
    cipher = Cipher(algorithms.AES(key), modes.ECB())
elif mode == "cbc":
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
elif mode == "gcm":
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv))

encryptor = cipher.encryptor()

if mode in ["ecb", "cbc"]:
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(in_data) + padder.finalize()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
elif mode == "gcm":
    encryptor.authenticate_additional_data(gcm_arg)
    encrypted_data = encryptor.update(in_data) + encryptor.finalize()
    tag = encryptor.tag

# Write encrypted data
write_file_in_bytes(out_filename, encrypted_data)

# Write GCM tag if applicable
if mode == "gcm":
    file_data = gcm_arg + b"\n" + tag
    print(file_data)
    write_file_in_bytes(gcm_arg_file, tag)