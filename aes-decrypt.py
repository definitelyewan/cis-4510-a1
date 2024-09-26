import sys
#https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption/
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
#https://cryptography.io/en/latest/hazmat/primitives/padding/
from cryptography.hazmat.primitives import padding

def usage():
    print("aes-decrypt usage:")
    print("\tkey=<a file name containing 128-bit key as a hex string>")
    print("\tiv<a file name containing IV as a hex string>")
    print("\tmode=ecb|cbc|gcm")
    print("\tin=<the input file name>")
    print("\tout=<the output file name>")
    print("\tgcm_args=<the name of a file, which contains a parameter for authentication>")
    print("aes-decrypt examples:")
    print("\taes-decrypt.py key=file_key iv=iv_file mode=cbc in=input_file out=out_file")
    print("\taes-decrypt.py key=file_key mode=ecb in=input_file out=out_file")

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
    usage()
    exit(1)

cmd_args = sys.argv
key = None
iv = None
mode = None
in_data = None
out_filename = None

if "mode=cbc" in cmd_args and not any(arg[:3] == "iv=" for arg in cmd_args):
    usage()
    exit(1)

if "mode=gcm" in cmd_args and not any(arg[:3] == "iv=" for arg in cmd_args) and not any(arg[:9] == "gcm_args=" for arg in cmd_args):
    usage()
    exit(1)

for i in range(1, len(sys.argv)):
    if cmd_args[i][:4] == "key=":
        key_hex = read_file_in_bytes(cmd_args[i][4:])
        if key_hex is None:
            usage()
            exit(1)
        key = bytes.fromhex(key_hex.decode().strip())
    elif cmd_args[i][:3] == "iv=":
        iv_hex = read_file_in_bytes(cmd_args[i][3:])
        if iv_hex is None:
            usage()
            exit(1)
        iv = bytes.fromhex(iv_hex.decode().strip())
    elif cmd_args[i][:9] == "gcm_args=":
        gcm_args = read_file_in_bytes(cmd_args[i][9:])
        if gcm_args is None:
            usage()
            exit(1)
    elif cmd_args[i][:5] == "mode=":
        mode = cmd_args[i][5:]
        if mode != "ecb" and mode != "cbc" and mode != "gcm":
            usage()
            exit(1)
    elif cmd_args[i][:3] == "in=":
        in_data = read_file_in_bytes(cmd_args[i][3:])
        if in_data is None:
            usage()
            exit(1)
    elif cmd_args[i][:4] == "out=":
        out_filename = cmd_args[i][4:]
        if out_filename is None:
            usage()
            exit(1)

if mode not in ["ecb", "cbc", "gcm"]:
    usage()
    exit(1)

#decrypt
cipher = None
encrypted_data = None

if mode == "ecb":
    cipher = Cipher(algorithms.AES(key), modes.ECB())
elif mode == "cbc":
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
elif mode == "gcm":
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, gcm_args, 16))

decryptor = cipher.decryptor()
decrypted_data = decryptor.update(in_data) + decryptor.finalize()

if mode in ["ecb", "cbc"]:
    unpadder = padding.PKCS7(128).unpadder()
    unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()
    write_file_in_bytes(out_filename, unpadded_data)

elif mode == "gcm":
    write_file_in_bytes(out_filename, decrypted_data)
