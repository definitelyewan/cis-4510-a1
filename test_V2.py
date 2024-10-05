import pickle, uuid, os, sys

def write_temp_files(case, temp_file_prefix):
    # Writing plaintext and ciphertext
    with open(temp_file_prefix + '_input.txt', 'wb') as f:
        f.write(case['plain text'])
    with open(temp_file_prefix + '_output.txt', 'wb') as f:
        f.write(case['cipher text'])
    with open(temp_file_prefix + '_key.txt', 'w') as f:
        f.write(str(case['key']))

    # Writing IV only if it exists (for CBC and GCM)
    if case['IV'] is not None:
        with open(temp_file_prefix + '_iv.txt', 'w') as f:
            f.write(str(case['IV']))

    # Writing additional data (AAD) only if it exists (for GCM)
    if case['additional'] is not None:
        with open(temp_file_prefix + '_additional.txt', 'wb') as f:
            f.write(case['additional'])


def delete_temp_files(temp_file_prefix):
    # Remove the temporary files created during the process
    for suffix in ['_input.txt', '_output.txt', '_output_dec.txt', '_output_enc.txt', '_key.txt', '_iv.txt', '_additional.txt']:
        path = temp_file_prefix + suffix
        if os.path.exists(path):
            os.remove(path)


def evaluate_case(case, temp_file_prefix):
    # Prepare the commands for different modes
    if case['mode'] == 'ecb':
        encrypt_command = f"python3 aes-encrypt.py -key {temp_file_prefix}_key.txt -input {temp_file_prefix}_input.txt -out {temp_file_prefix}_output_enc.txt -mode ecb"
        decrypt_command = f"python3 aes-decrypt.py -key {temp_file_prefix}_key.txt -input {temp_file_prefix}_output_enc.txt -out {temp_file_prefix}_output_dec.txt -mode ecb"
    elif case['mode'] == 'cbc':
        encrypt_command = f"python3 aes-encrypt.py -key {temp_file_prefix}_key.txt -input {temp_file_prefix}_input.txt -out {temp_file_prefix}_output_enc.txt -mode cbc -IV {temp_file_prefix}_iv.txt"
        decrypt_command = f"python3 aes-decrypt.py -key {temp_file_prefix}_key.txt -input {temp_file_prefix}_output_enc.txt -out {temp_file_prefix}_output_dec.txt -mode cbc -IV {temp_file_prefix}_iv.txt"
    elif case['mode'] == 'gcm':
        encrypt_command = f"python3 aes-encrypt.py -key {temp_file_prefix}_key.txt -input {temp_file_prefix}_input.txt -out {temp_file_prefix}_output_enc.txt -mode gcm -IV {temp_file_prefix}_iv.txt"
        if case['additional'] is not None:
            encrypt_command += f" -gcm_arg {temp_file_prefix}_additional.txt"
        decrypt_command = f"python3 aes-decrypt.py -key {temp_file_prefix}_key.txt -input {temp_file_prefix}_output_enc.txt -out {temp_file_prefix}_output_dec.txt -mode gcm -IV {temp_file_prefix}_iv.txt"
        if case['additional'] is not None:
            decrypt_command += f" -gcm_arg {temp_file_prefix}_additional.txt"

    try:
        # Perform encryption
        os.system(encrypt_command)
        with open(temp_file_prefix + '_output_enc.txt', 'rb') as f:
            enc_text = f.read()

        # Handle GCM mode separately to manage the tag
        if case['mode'] == 'gcm':
            ciphertext = enc_text[:-16]  # Extract ciphertext (minus tag)
            tag = enc_text[-16:]  # Extract tag

            # Debugging information
            print(f"[Encryption] Extracted Tag: {tag.hex()}")
            print(f"[Encryption] IV used: {open(temp_file_prefix + '_iv.txt').read().strip()}")
            print(f"[Encryption] Additional Authenticated Data (AAD): {open(temp_file_prefix + '_additional.txt', 'rb').read().hex() if case['additional'] is not None else 'None'}")

            # Compare encrypted output with expected ciphertext and tag
            with open(temp_file_prefix + '_output.txt', 'rb') as f:
                expected_enc_text = f.read()

            expected_ciphertext = expected_enc_text[:-16]
            expected_tag = expected_enc_text[-16:]
            success_encrypt = (ciphertext == expected_ciphertext) and (tag == expected_tag)

            if not success_encrypt:
                print("[Mismatch] Ciphertext or Tag Mismatch Detected for GCM Mode.")
                print(f"Expected Ciphertext: {expected_ciphertext.hex()}")
                print(f"Generated Ciphertext: {ciphertext.hex()}")
                print(f"Expected Tag: {expected_tag.hex()}")
                print(f"Generated Tag: {tag.hex()}")

        else:
            # For ECB and CBC modes, directly compare the encrypted texts
            with open(temp_file_prefix + '_output.txt', 'rb') as f:
                expected_enc_text = f.read()

            success_encrypt = (enc_text == expected_enc_text)

    except Exception as e:
        print(f"[Encryption Error]: {e}")
        success_encrypt = False

    # Perform decryption
    try:
        os.system(decrypt_command)
        with open(temp_file_prefix + '_output_dec.txt', 'rb') as f:
            dec_text = f.read()
        with open(temp_file_prefix + '_input.txt', 'rb') as f:
            expected_plaintext = f.read()

        success_decrypt = (dec_text == expected_plaintext)

        if not success_decrypt:
            print("[Decryption Mismatch] Decryption mismatch detected.")
            print(f"Expected Plaintext: {expected_plaintext.hex()}")
            print(f"Generated Plaintext: {dec_text.hex()}")

    except Exception as e:
        print(f"[Decryption Error]: {e}")
        success_decrypt = False

    delete_temp_files(temp_file_prefix)
    return success_encrypt, success_decrypt


# Load the test cases
object_file = open('cases.crypt', 'rb')
cases = pickle.load(object_file)
object_file.close()
print('# Test cases are loaded')
print(f'Your developed encryption/decryption scripts are evaluated by {len(cases.keys())} test cases.')
marks = [[0, 0], [0, 0]]
for case_key, case in cases.items():
    print(f'  {case_key}:')
    temp_file_prefix = str(uuid.uuid4())

    try:
        write_temp_files(case, temp_file_prefix)
        results = evaluate_case(case, temp_file_prefix)
    except Exception as e:
        print(f"######## Error for {case_key}")
        print(f"\tError: {e}")
        results = (False, False)

    if case['mode'] == 'gcm':
        marks[1][1] += 2
        if results[0]:
            marks[1][0] += 1
            print('        Successful Encryption ')
        else:
            print('        Unsuccessful Encryption')
        if results[1]:
            marks[1][0] += 1
            print('        Successful Decryption')
        else:
            print('        Unsuccessful Decryption')
    else:
        marks[0][1] += 2
        if results[0]:
            marks[0][0] += 1
            print('        Successful Encryption')
        else:
            print('        Unsuccessful Encryption')
        if results[1]:
            marks[0][0] += 1
            print('        Successful Decryption')

print('*** Your Final Mark for 2.a is < {p1:.2f} of 3> and for 2.e is < {p2:.2f} of 2> ***\n'.format(
    p1=(marks[0][0] / marks[0][1] * 3) if marks[0][1] > 0 else 0,
    p2=(marks[1][0] / marks[1][1] * 2) if marks[1][1] > 0 else 0))
