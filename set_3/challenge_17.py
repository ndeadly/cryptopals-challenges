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

    c1 = iv
    for i in range(0, len(ciphertext), block_size):
        c2 = ciphertext[i:i+block_size]
        #print(c1.hex(), c2.hex())
        c1_mod = bytearray(c1)
        for j in range(block_size-1, 0, -1):
            for k in range(256):
                c1_mod[j] = k
                #print(c1_mod.hex())
                if consume_session_token((iv, c1_mod + c2)):
                    dk_c2 = chr(c1_mod[j] ^ (block_size-j))
                    print(dk_c2)
                    break

        c1 = c2


if __name__ == '__main__':
    main()
