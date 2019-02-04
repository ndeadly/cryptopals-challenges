import secrets

from set_1.challenge_7 import aes_ecb
from set_2.challenge_10 import aes_cbc
from set_1.challenge_8 import using_aes_ecb
from set_2.challenge_9 import pkcs7_pad_plaintext


def encryption_oracle(input_data):
    # Generate random key
    key = secrets.token_bytes(16)

    # Add 5-10 random bytes before and after the plaintext
    input_data = secrets.token_bytes(secrets.randbelow(6)+5) + input_data + secrets.token_bytes(secrets.randbelow(6)+5)

    # Pad the input data to multiple of block size
    input_data = pkcs7_pad_plaintext(input_data, 16)

    # Select AES mode and encrypt
    if secrets.randbelow(2) == 0:
        print('Oracle chose ECB mode')
        return aes_ecb(input_data, key, operation='encrypt')
    else:
        print('Oracle chose CBC mode')
        iv = secrets.token_bytes(16)
        return aes_cbc(input_data, key, iv, operation='encrypt')


def detect_aes_mode(encryption_func):
    # Set plaintext to be 4 blocks of zeros
    plaintext = bytes(16*4)

    # Encrpyt the zeros
    ciphertext = encryption_func(plaintext)

    # Check for evidence of ECB mode (repeated ciphertext/plaintext pairs) , otherwise assume CBC
    if using_aes_ecb(ciphertext):
        return 'ECB'
    else:
        return 'CBC'


if __name__ == '__main__':
    mode = detect_aes_mode(encryption_oracle)
    print('Detected AES-{} mode in use'.format(mode))
