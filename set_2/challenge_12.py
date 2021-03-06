import base64
import secrets

from set_1.challenge_6 import hamming_distance
from set_1.challenge_7 import aes_ecb
from set_2.challenge_9 import pkcs7_pad_plaintext
from set_2.challenge_11 import detect_aes_mode


unknown_plaintext = '''Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK'''

# Generate random key
secret_key = secrets.token_bytes(16)


def encryption_oracle(input_data):

    input_data = input_data + base64.b64decode(unknown_plaintext)

    # Pad the input data to multiple of block size
    input_data = pkcs7_pad_plaintext(input_data, 16)

    return aes_ecb(input_data, secret_key, operation='encrypt')


def detect_block_size(encryption_func):
    block_size = -1
    for i in range(1, 256+1):
        if hamming_distance(encryption_func(b'A'*i), encryption_func(b'A'*(i+1))[:i]) == 0:
            block_size = i
            break

    return block_size


def main():
    block_size = detect_block_size(encryption_oracle)
    print('block size:', block_size)

    mode = detect_aes_mode(encryption_oracle)
    print('Oracle is using AES-{}'.format(mode))

    print('Decrypting ciphertext...')

    pos = 0
    output = []
    while True:
        q, r = divmod(pos, block_size)

        input_block = b'A'*(block_size-(r+1))

        d = dict()
        for i in range(256):
            ciphertext = encryption_oracle(input_block + bytes(output) + i.to_bytes(1, 'little'))
            d[ciphertext[q*block_size:q*block_size + block_size].hex()] = i

        try:
            output_byte = d[encryption_oracle(input_block)[q*block_size:q*block_size + block_size].hex()]
        except KeyError:
            break

        output.append(output_byte)
        pos += 1

        print(chr(output_byte), end='', flush=True)


if __name__ == '__main__':
    main()
