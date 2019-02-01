import base64
from itertools import combinations

from set_1.challenge_2 import xor_buffers
from set_1.challenge_3 import find_single_byte_xor_key
from set_1.challenge_5 import repeating_key_xor


def hamming_distance(buff1, buff2):
    return sum(bin(ch).count('1') for ch in xor_buffers(buff1, buff2))


if __name__ == '__main__':
    input1 = b'this is a test'
    input2 = b'wokka wokka!!!'
    assert(hamming_distance(input1, input2) == 37)

    # Load encrypted data from file
    with open('6.txt', 'r') as f:
        ciphertext = base64.b64decode(f.read())

    # Find hamming distances for range of key sizes
    results = []
    for key_size in range(2, 41):
        # Take first 4 key_size blocks
        blocks = [ciphertext[i*key_size:(i+1)*key_size] for i in range(4)]
        # Compute all combinations of hamming distances between the blocks
        distances = [hamming_distance(b[0], b[1]) for b in combinations(blocks, 2)]
        # Compute the average hamming distance between the 4 blocks
        avg_dist = sum(distances) / len(distances)
        # Normalise the distance value
        dist_norm = avg_dist / key_size
        results.append((key_size, dist_norm))

    # Sort tuples according to normalised hamming distance score
    results = sorted(results, key=lambda x: x[1])
    # Take first result with lowest score to be keysize
    key_size, score = results[0]

    key = b''
    for i in range(key_size):
        # Assemble the ith transposed data block
        indices = range(i, len(ciphertext), key_size)
        block = bytes([ciphertext[j] for j in indices])
        # Find single byte xor key for transposed block
        block_key = find_single_byte_xor_key(block)
        # Add block key to the final key
        key += block_key

    print('key size:', key_size)
    print('key:', key)
    print('ciphertext:', ciphertext.hex())
    plaintext = repeating_key_xor(ciphertext, key)
    print('plaintext:', plaintext.decode())
