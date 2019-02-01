from set_1.challenge_7 import aes_decrypt_block


def using_aes_ecb(ciphertext):
    # Create an empty dictionary (hashmap)
    hmap = dict()
    for i in range(0, len(ciphertext), 16):
        # Take next 16 byte block of ciphertext
        ctext_block = bytearray(ciphertext[i:i + 16])

        # Decrypt block with all-zero key
        ptext_block = aes_decrypt_block(ctext_block, bytes(16))

        try:
            if ctext_block in hmap[ptext_block.hex()]:
                # If there's already an entry for this pair in the map,
                # we've found a ciphertext using AES-RCB
                return True
            else:
                # Add alternate mapping in the case of a collision
                hmap[ptext_block.hex()].append(ctext_block)

        except KeyError:
            # Add new unique plaintext/ciphertext pair to the map
            hmap[ptext_block.hex()] = [ctext_block]

    return False


if __name__ == '__main__':

    with open('8.txt', 'r') as f:
        ciphertexts = map(bytes.fromhex, f.read().splitlines())

    ecb_ciphertexts = [c for c in ciphertexts if using_aes_ecb(c)]

    print('ciphertexts using AES-ECB:')
    for ciphertext in ecb_ciphertexts:
        print(ciphertext.hex())
