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

    return ciphertext, iv


def consume_session_token(token):
    ciphertext, iv = token
    plaintext = aes_cbc(ciphertext, secret_key, iv, operation='decrypt')
    try:
        strip_pkcs7_padding(plaintext, block_size)
    except PaddingException:
        return False
    else:
        return True


def main():
    token = generate_session_token()
    ciphertext, iv = token
    print(ciphertext.hex(), iv.hex())
    for i in range(len(ciphertext)):
        for j in range(256):
            corrupted = bytearray(ciphertext.copy())
            corrupted[i] = j
            correct_padding = consume_session_token((corrupted, iv))
            print(correct_padding)
            '''
            if correct_padding:
                print(chr(j))
                break
            '''


if __name__ == '__main__':
    main()
