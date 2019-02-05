import secrets
from urllib.parse import quote

from set_2.challenge_9 import pkcs7_pad_plaintext
from set_2.challenge_10 import aes_cbc
from set_2.challenge_13 import parse_qs
from set_2.challenge_14 import detect_prefix_length
from set_2.challenge_15 import strip_pkcs7_padding


str1 = b'comment1=cooking%20MCs;userdata='
str2 = b';comment2=%20like%20a%20pound%20of%20bacon'

secret_key = secrets.token_bytes(16)
iv = secrets.token_bytes(16)


def encrypted_query(userdata):
    query = str1 + bytes(quote(userdata).encode('ascii')) + str2
    print(query)
    ciphertext = aes_cbc(pkcs7_pad_plaintext(query, 16), secret_key, iv, operation='encrypt')
    return ciphertext


def contains_admin_argument(ciphertext):
    plaintext = aes_cbc(ciphertext, secret_key, iv, operation='decrypt')
    print(plaintext)
    query = strip_pkcs7_padding(plaintext, 16)
    print('query:', query)
    query_obj = parse_qs(query)
    print('query obj:', query_obj)
    return 'admin' in query_obj


def main():
    block_size = 16

    prefix_length = detect_prefix_length(encrypted_query, block_size)
    print('prefix length:', prefix_length)

    userdata = b'AadminAtrue'

    ciphertext = encrypted_query(userdata)
    print(ciphertext.hex())
    ciphertext[prefix_length-block_size] ^= ord('A') ^ ord(';')
    ciphertext[prefix_length-block_size+6] ^= ord('A') ^ ord('=')
    #print(ciphertext[prefix_length-block_size])
    #print(ciphertext.hex())

    print('Admin field present?:', contains_admin_argument(ciphertext))


if __name__ == '__main__':
    main()
