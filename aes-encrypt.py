
import sys

def usage():
    print("aes-encrypt usage:")
    print("\tkey=<a file name containing 128-bit key as a hex string>")
    print("\tIV<a file name containing IV as a hex string>")
    print("\tmode=ecb|cbc")
    print("\tin=<the input file name>")
    print("\tout=<the output file name>")
    print("aes-encrypt examples:")
    print("\taes-encrypt.py key=file_key IV=iv_file mode=cbc in=input_file out=out_file")
    print("\taes-encrypt.py key=file_key mode=ecb in=input_file out=out_file")



arg_len = len(sys.argv)

if arg_len < 5:
    usage()
    exit(1)


cmd_args = sys.argv
key_filename = None
iv_filename = None
mode = None
in_filename = None
out_filename = None


if "mode=cbc" in cmd_args and not any(arg[:3] == "IV=" for arg in cmd_args):
    usage()
    exit(1)






for i in range(1, arg_len):
    print(sys.argv[i], end=" ")

print(arg_len)
