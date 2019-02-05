
class PaddingException(Exception):
    pass


def strip_pkcs7_padding(plaintext, block_size):
    if len(plaintext) % block_size == 0:
        pad_length = plaintext[-1]
        if pad_length <= block_size and all(b == pad_length for b in plaintext[-pad_length:]):
            return plaintext[:-pad_length]

    raise PaddingException('Incorrect padding')


def main():
    for plaintext in [b'ICE ICE BABY\x04\x04\x04\x04',
                      b'ICE ICE BABY\x01\x02\x03\x04',
                      b'ICE ICE BABY\x05\x05\x05\x05']:
        try:
            stripped = strip_pkcs7_padding(plaintext, 16)
        except PaddingException:
            print('Incorrect padding:\t', plaintext)
        else:
            print('Correct padding:\t', plaintext, stripped)


if __name__ == '__main__':
    main()
