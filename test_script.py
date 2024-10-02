import pickle, uuid, os, sys

def write_temp_files(case,temp_file_prefix):
    f=open(temp_file_prefix + '_input.txt','wb')
    f.write(case['plain text'])
    f.close()
    f=open(temp_file_prefix + '_output.txt','wb')
    f.write(case['cipher text'])
    f.close()
    f=open(temp_file_prefix + '_key.txt','w')
    f.write(str(case['key']))
    f.close()
    f=open(temp_file_prefix + '_iv.txt','w')
    f.write(str(case['IV']))
    f.close()
    f=open(temp_file_prefix + '_additional.txt','wb')
    f.write(case['additional'])
    f.close()
    f=open(temp_file_prefix + '_tag.txt','wb')
    f.write(case['tag'])
    f.close()

def delete_temp_files(temp_file_prefix):
    os.remove(temp_file_prefix + '_input.txt') if os.path.exists(temp_file_prefix + '_input.txt') else None
    os.remove(temp_file_prefix + '_output.txt') if os.path.exists(temp_file_prefix + '_output.txt') else None
    os.remove(temp_file_prefix + '_output_dec.txt') if os.path.exists(temp_file_prefix + '_output_dec.txt') else None
    os.remove(temp_file_prefix + '_output_enc.txt') if os.path.exists(temp_file_prefix + '_output_enc.txt') else None
    os.remove(temp_file_prefix + '_key.txt') if os.path.exists(temp_file_prefix + '_key.txt') else None
    os.remove(temp_file_prefix + '_iv.txt') if os.path.exists(temp_file_prefix + '_iv.txt') else None
    os.remove(temp_file_prefix + '_additional.txt') if os.path.exists(temp_file_prefix + '_additional.txt') else None
    os.remove(temp_file_prefix + '_tag.txt') if os.path.exists(temp_file_prefix + '_tag.txt') else None
    return

def evaluate_case(case,temp_file_prefix):
    if case['mode']=='ecb':
        encrypt_command="python3 aes-encrypt.py -key {key_file} -input {input_file} -out {output_file} -mode ecb".format(\
                               key_file=temp_file_prefix + '_key.txt' , \
                               input_file=temp_file_prefix + '_input.txt', \
                               output_file=temp_file_prefix + '_output_enc.txt')
        decrypt_command = "python3 aes-decrypt.py -key {key_file} -in {input_file} -out {output_file} -mode ecb".format( \
            key_file=temp_file_prefix + '_key.txt', \
            input_file=temp_file_prefix + '_output.txt', \
            output_file=temp_file_prefix + '_output_dec.txt')
    elif case['mode'] == 'cbc':
        encrypt_command="python3 aes-encrypt.py -key {key_file} -input {input_file} -out {output_file} -mode cbc -IV {IV_file}".format(\
                               key_file=temp_file_prefix + '_key.txt' , \
                               input_file=temp_file_prefix + '_input.txt', \
                               output_file=temp_file_prefix + '_output_enc.txt', \
                               IV_file =   temp_file_prefix + '_iv.txt')
        decrypt_command = "python3 aes-decrypt.py -key {key_file} -in {input_file} -out {output_file} -mode cbc -IV {IV_file}".format( \
            key_file=temp_file_prefix + '_key.txt', \
            input_file=temp_file_prefix + '_output.txt', \
            output_file=temp_file_prefix + '_output_dec.txt',\
            IV_file =   temp_file_prefix + '_iv.txt')
    elif case['mode'] == 'gcm':
        encrypt_command="python3 aes-encrypt.py -key {key_file} -input {input_file} -out {output_file} -mode gcm -IV {IV_file} -gcm_arg {additional_file}".format(\
                               key_file=temp_file_prefix + '_key.txt' , \
                               input_file=temp_file_prefix + '_input.txt', \
                               output_file=temp_file_prefix + '_output_enc.txt', \
                               IV_file =   temp_file_prefix + '_iv.txt',\
                               additional_file = temp_file_prefix + '_additional.txt')
        decrypt_command = "python3 aes-decrypt.py -key {key_file} -in {input_file} -out {output_file} -mode gcm -IV {IV_file} -gcm_arg {additional_file}".format( \
            key_file=temp_file_prefix + '_key.txt', \
            input_file=temp_file_prefix + '_output.txt', \
            output_file=temp_file_prefix + '_output_dec.txt',\
            IV_file =   temp_file_prefix + '_iv.txt',\
            additional_file = temp_file_prefix + '_additional.txt')

    try:
        os.system(encrypt_command)
        f=open(temp_file_prefix + '_output_enc.txt','rb')
        enc_text=f.readlines()
        f.close()
        f=open(temp_file_prefix + '_output.txt','rb')
        enc_text_case=f.readlines()
        f.close()
        success_encrypt=(enc_text==enc_text_case)
    except:
        success_encrypt =False
    try:
        os.system(decrypt_command)
        f=open(temp_file_prefix + '_output_dec.txt','rb')
        dec_text=f.readlines()
        f.close()
        f=open(temp_file_prefix + '_input.txt','rb')
        dec_text_case=f.readlines()
        f.close()
        success_decrypt = (dec_text == dec_text_case)
    except:
        success_decrypt=False
    delete_temp_files(temp_file_prefix)
    return success_encrypt, success_decrypt


object_file=open('cases.crypt', 'rb')
cases=pickle.load( object_file)
object_file.close()
print('# Test cases are loaded')
print('Your developed encryption/decryption scripts are evaluated by %d test case'%(len(cases.keys())))
marks=[[0,0],[0,0]]
for case_key in cases.keys():
    case=cases[case_key]
    print('\t', case_key,':')
    temp_file_prefix=str(uuid.uuid4())
    # Uncomment  next two lines  if you want to see the case detail
    for case_item_key in cases[case_key]:
        print('\t \t ', case_item_key, ':' ,case[case_item_key])

    try:
        try:
            write_temp_files(case, temp_file_prefix)
            results = evaluate_case(case, temp_file_prefix)
            delete_temp_files(temp_file_prefix)
        except:
            results= (False,False)
        if case['mode']=='gcm':
            marks[1][1] = marks[1][1] + 2
            if results[0]:
                marks[1][0]= marks[1][0]+1
                print('\t\tSuccessful Encryption ')
            else:
                print('\t\tUnsuccessful Encryption')
            if results[1]:
                marks[1][0]= marks[1][0]+1
                print('\t\tSuccessful Decryption')
            else:
                print('\t\tUnsuccessful Decryption')
        else:
            marks[0][1] = marks[0][1] + 2
            if results[0]:
                marks[0][0] = marks[0][0] + 1
                print('\t\tSuccessful Encryption')
            else:
                print('\t\tUnsuccessful Encryption')
            if results[1]:
                marks[0][0] = marks[0][0] + 1
                print('\t\tSuccessful Decryption')
            else:
                print('\t\tUnsuccessful Decryption')
    except:
        print('########Error for ', case_key)
        print("\tError :", sys.exc_info()[0])
        print("\tError Detail :", sys.exc_info()[1])
        delete_temp_files(temp_file_prefix)

print('*** Your Final Mark for 2.a is < {p1} of 3> and for 2.e is  < {p2} of 2>***\n'.format(p1=marks[0][0]/marks[0][1]*3,p2=marks[1][0]/marks[1][1]*2))








