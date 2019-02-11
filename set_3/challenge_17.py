import base64
import secrets

from set_2.challenge_9 import pkcs7_pad_plaintext
from set_2.challenge_10 import aes_cbc
from set_2.challenge_15 import strip_pkcs7_padding, PaddingException


strings = ['MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=',
           'MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=',
           'MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==',
           'MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==',
           'MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl',
           'MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==',
           'MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==',
           'MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=',
           'MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=',
           'MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93']


block_size = 16
secret_key = secrets.token_bytes(16)


def generate_session_token():
    string = secrets.choice(strings)
    plaintext = base64.b64decode(string)
    padded_plaintext = pkcs7_pad_plaintext(plaintext, block_size)

    iv = secrets.token_bytes(16)
    ciphertext = aes_cbc(padded_plaintext, secret_key, iv, operation='encrypt')

    return iv, ciphertext


def consume_session_token(token):
    iv, ciphertext = token
    plaintext = aes_cbc(ciphertext, secret_key, iv, operation='decrypt')
    try:
        strip_pkcs7_padding(plaintext, block_size)
    except PaddingException:
        return False
    else:
        return True


def main():
    token = generate_session_token()
    iv, ciphertext = token

    plaintext = b''

    c1 = iv
    for i in range(0, len(ciphertext), block_size):
        # Take next block to decrypt
        c2 = ciphertext[i:i+block_size]

        # Init plaintext block
        p2 = bytearray(block_size)

        # Check for last block
        if i == len(ciphertext) - block_size:
            for b in range(block_size):
                c1_mod = bytearray(c1)
                c1_mod[b] ^= 1
                if not consume_session_token((iv, c1_mod + c2)):
                    padding_byte = block_size-b
                    start_byte = block_size-padding_byte-1
                    p2[-padding_byte:] = bytes([padding_byte]*padding_byte)
                    break
        else:
            start_byte = block_size-1

        for j in range(start_byte, -1, -1):
            c1_mod = bytearray(c1)

            padding_byte = block_size-j
            for b in range(1, padding_byte):
                c1_mod[-b] ^= p2[-b] ^ padding_byte

            for k in range(256):
                c1_mod[j] = c1[j] ^ k
                if consume_session_token((iv, c1_mod + c2)):
                    p2[j] = k ^ padding_byte
                    break

        # Append decrypted block to plaintext
        plaintext += p2
        print('Decrypted block:', p2)

        c1 = c2

    print()
    print('Plaintext:', strip_pkcs7_padding(plaintext, block_size).decode())


if __name__ == '__main__':
    main()
