from set_1.challenge_2 import xor_buffers


def repeating_key_xor(data, key):
    key_data = bytes([key[i % len(key)] for i in range(len(data))])
    return xor_buffers(data, key_data)


def main():
    key = b'ICE'
    plaintext = b'Burning \'em, if you ain\'t quick and nimble\nI go crazy when I hear a cymbal'
    ciphertext = bytes.fromhex('0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430'
                               'a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f')

    result = repeating_key_xor(plaintext, key)
    print(result.hex())
    assert(result == ciphertext)


if __name__ == '__main__':
    main()
