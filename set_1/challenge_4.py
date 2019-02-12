from set_1.challenge_3 import score_plaintext, single_byte_repeating_xor


def main():
    with open('4.txt', 'r') as f:
        ciphertexts = [bytes.fromhex(ln) for ln in f.read().splitlines()]

    scores = []
    for ciphertext in ciphertexts:
        for i in range(256):
            key = i.to_bytes(1, 'little')
            decrypted = single_byte_repeating_xor(ciphertext, key)
            score = score_plaintext(decrypted)
            scores.append(score)

    line_num, char = divmod(scores.index(max(scores)), 256)
    ciphertext = ciphertexts[line_num]
    key = char.to_bytes(1, 'little')
    plaintext = single_byte_repeating_xor(ciphertext, key)

    print('line number:', line_num)
    print('key:\t\t', key)
    print('cyphertext:\t', ciphertext.hex())
    print('plaintext:\t', plaintext.decode())


if __name__ == '__main__':
    main()
