import secrets

from set_1.challenge_6 import hamming_distance
from set_2.challenge_12 import encryption_oracle as oracle_challenge_12


random_prefix = secrets.token_bytes(secrets.randbelow(256))


def encryption_oracle(input_data):
    return oracle_challenge_12(random_prefix + input_data)


def detect_prefix_length(encryption_func, block_size):
    # Determine amount of full blocks covered by prefix
    n_blocks = 1
    while hamming_distance(encryption_func(b'A')[:block_size * n_blocks],
                           encryption_func(b'A' * 2)[:block_size * n_blocks]) == 0:
        n_blocks += 1

    prefix_length = 0
    for i in range(1, block_size+2):
        if hamming_distance(encryption_func(b'A'*i)[:block_size*n_blocks],
                            encryption_func(b'A'*(i+1))[:block_size*n_blocks]) == 0:
            prefix_length = block_size*n_blocks - i
            break

    return prefix_length


def main():
    block_size = 16
    prefix_length = detect_prefix_length(encryption_oracle, block_size)
    print('Detected prefix length:', prefix_length)

    print('Decrypting ciphertext...')

    pos = prefix_length
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
