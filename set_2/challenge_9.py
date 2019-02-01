
def pkcs7_pad_plaintext(plaintext, block_size):
    pad_bytes = block_size - (len(plaintext) % block_size)
    return plaintext + bytes([pad_bytes] * pad_bytes)


if __name__ == '__main__':
    plaintext = b'YELLOW SUBMARINE'
    padded_plaintext = pkcs7_pad_plaintext(plaintext, 20)
    assert(padded_plaintext == b'YELLOW SUBMARINE\x04\x04\x04\x04')
