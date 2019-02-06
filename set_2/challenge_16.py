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
    ciphertext = aes_cbc(pkcs7_pad_plaintext(query, 16), secret_key, iv, operation='encrypt')
    return ciphertext


def is_admin(ciphertext):
    plaintext = aes_cbc(ciphertext, secret_key, iv, operation='decrypt')
    query = strip_pkcs7_padding(plaintext, 16)
    query_obj = parse_qs(query)
    return ('admin' in query_obj) and (query_obj['admin'] == 'true')


def main():
    block_size = 16

    prefix_length = detect_prefix_length(encrypted_query, block_size)

    # Compute number of extra bytes required so that our userdata is placed at the start of a block
    n = block_size - (prefix_length % block_size)

    # Construct userdata string of n (P)adding bytes, a full block of (C)orruptable bytes, and the string we want to
    # inject with invalid characters
    userdata = b'P'*n + b'C'*block_size + b'FadminFtrue'

    # Generate encrypted query from the userdata string
    ciphertext = encrypted_query(userdata)
    print('Admin status before bit flipping:', is_admin(ciphertext))

    # Flip bits in the corruptable block to transform the F's in our userdata into the required invalid characters
    ciphertext[prefix_length+n+0] ^= ord('F') ^ ord(';')
    ciphertext[prefix_length+n+6] ^= ord('F') ^ ord('=')
    print('Admin status after bit flipping:', is_admin(ciphertext))


if __name__ == '__main__':
    main()
