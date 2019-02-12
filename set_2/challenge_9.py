
def pkcs7_pad_plaintext(plaintext, block_size):
    pad_bytes = block_size - (len(plaintext) % block_size)
    return plaintext + bytes([pad_bytes] * pad_bytes)


def main():
    plaintext = b'YELLOW SUBMARINE'
    padded_plaintext = pkcs7_pad_plaintext(plaintext, 20)
    print('plaintext:', plaintext)
    print('padded plaintext:', padded_plaintext)
    assert(padded_plaintext == b'YELLOW SUBMARINE\x04\x04\x04\x04')


if __name__ == '__main__':
    main()
