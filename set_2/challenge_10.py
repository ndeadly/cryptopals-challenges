import base64

from set_1.challenge_2 import xor_buffers
from set_1.challenge_7 import expand_key, aes_encrypt_block, aes_decrypt_block


def aes_cbc(input_data, key, iv, operation='encrypt'):
    key_bits = len(key)*8
    if key_bits not in [128, 192, 256]:
        raise ValueError('Wrong size key. Must be either 128, 192 or 256 bits')

    key_schedule = expand_key(key)

    input_data = bytearray(input_data)
    output_data = bytearray(len(input_data))
    for i in range(0, len(input_data), 16):
        if operation == 'encrypt':
            if i == 0:
                block = xor_buffers(input_data[i:i+16], iv)
            else:
                block = xor_buffers(input_data[i:i+16], output_data[i-16:i])

            aes_encrypt_block(block, key_schedule)
            output_data[i:i + 16] = block

        elif operation == 'decrypt':
            block = input_data[i:i+16]
            aes_decrypt_block(block, key_schedule[::-1])

            if i == 0:
                output_data[i:i+16] = xor_buffers(block, iv)
            else:
                output_data[i:i+16] = xor_buffers(block, input_data[i-16:i])

    return output_data


def main():
    with open('10.txt', 'r') as f:
        ciphertext = base64.b64decode(f.read())

    print(ciphertext)

    key = b'YELLOW SUBMARINE'
    iv = bytes(16)

    plaintext = aes_cbc(ciphertext, key, iv, operation='decrypt')
    print(aes_cbc(plaintext, key, iv, operation='encrypt'))
    print(plaintext.decode())


if __name__ == '__main__':
    main()
