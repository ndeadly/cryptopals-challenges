import base64

from set_1.challenge_2 import xor_buffers
from set_1.challenge_7 import expand_key, aes_encrypt_block


def aes_ctr(input_data, key, nonce, format='little'):
    key_bits = len(key)*8
    if key_bits not in [128, 192, 256]:
        raise ValueError('Wrong size key. Must be either 128, 192 or 256 bits')

    key_schedule = expand_key(key)

    input_data = bytearray(input_data)
    output_data = bytearray(len(input_data))

    counter = 0

    for i in range(0, len(input_data), 16):
        data_block = input_data[i:i+16]
        counter_block = bytearray(nonce.to_bytes(8, format) + counter.to_bytes(8, format))
        aes_encrypt_block(counter_block, key_schedule)
        output_data[i:i+16] = xor_buffers(data_block, counter_block)

        counter += 1

    return output_data


def main():
    string = b'L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=='

    ciphertext = base64.b64decode(string)
    key = b'YELLOW SUBMARINE'
    nonce = 0

    plaintext = aes_ctr(ciphertext, key, nonce, format='little')
    print(plaintext.decode())


if __name__ == '__main__':
    main()
