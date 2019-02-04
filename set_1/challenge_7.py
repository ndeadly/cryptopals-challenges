import base64

from set_1.challenge_2 import xor_buffers


def generate_round_constants(n_rounds):
    constants = []
    for i in range(n_rounds):
        if i == 0:
            rc = 0
        if i == 1:
            rc = 1
        elif i > 1 and rcon[0] < 0x80:
            rc = 2 * rcon[0]
        elif i > 1 and rcon[0] >= 0x80:
            rc = (2 * rcon[0]) ^ 0x11b

        rcon = bytes([rc, 0, 0, 0])
        constants.append(rcon)

    return constants


def left_circ_shift(b, n):
    return ((b << n) | (b >> 8-n)) & 0xff


def compute_s_box():
    ''' Translated from C code found at https://en.wikipedia.org/wiki/Rijndael_S-box '''

    p = 1
    q = 1
    s = [0]*256
    while True:
        p = (p ^ ((p << 1) & 0xff) ^ (0x1b if (p & 0x80) else 0))

        q ^= (q << 1) & 0xff
        q ^= (q << 2) & 0xff
        q ^= (q << 4) & 0xff
        q ^= 0x09 if (q & 0x80) else 0

        s[p] = q ^ left_circ_shift(q, 1) ^ left_circ_shift(q, 2) ^ left_circ_shift(q, 3) ^ left_circ_shift(q, 4) ^ 0x63

        if p == 1:
            break

    s[0] = 0x63

    return s


sbox = compute_s_box()
inv_sbox = sorted(range(256), key=lambda x: sbox[x])


def sub_bytes(input_block):
    for i in range(len(input_block)):
        input_block[i] = sbox[input_block[i]]

    return input_block


def inv_sub_bytes(input_block):
    for i in range(len(input_block)):
        input_block[i] = inv_sbox[input_block[i]]

    return input_block


def shift_rows(input_block):
    b = input_block
    b[1], b[5], b[9], b[13] = b[5], b[9], b[13], b[1]
    b[2], b[6], b[10], b[14] = b[10], b[14], b[2], b[6]
    b[3], b[7], b[11], b[15] = b[15], b[3], b[7], b[11]

    return input_block


def inv_shift_rows(input_block):
    b = input_block
    b[1], b[5], b[9], b[13] = b[13], b[1], b[5], b[9]
    b[2], b[6], b[10], b[14] = b[10], b[14], b[2], b[6]
    b[3], b[7], b[11], b[15] = b[7], b[11], b[15], b[3]

    return input_block


def compute_gf_256_table():

    def _g_mul(b1, b2):
        ''' Translated from C# example from https://en.wikipedia.org/wiki/Rijndael_MixColumns '''

        p = 0
        for i in range(8):
            if (b1 & 1) != 0:
                p ^= b2

            hi_bit_set = (b2 & 0x80) != 0
            b2 = (b2 << 1) & 0xff
            if hi_bit_set:
                b2 ^= 0x1B

            b1 = (b1 >> 1) & 0xff

        return p

    table = [0] * (256 * 256)
    for a in range(256):
        for b in range(256):
            table[a*256 + b] = _g_mul(a, b)

    return table


gf_256_mul = compute_gf_256_table()


def g_mul(b1, b2):
    return gf_256_mul[b1*256 + b2]


def mix_columns(input_block):
    for i in range(0, 16, 4):
        b = input_block[i:i+4]
        d0 = g_mul(b[0], 2) ^ g_mul(b[1], 3) ^ b[2] ^ b[3]
        d1 = b[0] ^ g_mul(b[1], 2) ^ g_mul(b[2], 3) ^ b[3]
        d2 = b[0] ^ b[1] ^ g_mul(b[2], 2) ^ g_mul(b[3], 3)
        d3 = g_mul(b[0], 3) ^ b[1] ^ b[2] ^ g_mul(b[3], 2)
        input_block[i+0] = d0
        input_block[i+1] = d1
        input_block[i+2] = d2
        input_block[i+3] = d3

    return input_block


def inv_mix_columns(input_block):
    for i in range(0, 16, 4):
        d = input_block[i:i+4]
        b0 = g_mul(d[0], 14) ^ g_mul(d[1], 11) ^ g_mul(d[2], 13) ^ g_mul(d[3], 9)
        b1 = g_mul(d[0], 9) ^ g_mul(d[1], 14) ^ g_mul(d[2], 11) ^ g_mul(d[3], 13)
        b2 = g_mul(d[0], 13) ^ g_mul(d[1], 9) ^ g_mul(d[2], 14) ^ g_mul(d[3], 11)
        b3 = g_mul(d[0], 11) ^ g_mul(d[1], 13) ^ g_mul(d[2], 9) ^ g_mul(d[3], 14)
        input_block[i+0] = b0
        input_block[i+1] = b1
        input_block[i+2] = b2
        input_block[i+3] = b3

    return input_block


def add_round_key(input_block, round_key):
    for i in range(len(input_block)):
        input_block[i] ^= round_key[i]

    return input_block


def rot_word(word):
    return word[1:] + word[:1]


def sub_word(word):
    return bytes(sbox[b] for b in word)


def expand_key(key):
    N = len(key) // 4
    R = N + 7

    rcon = generate_round_constants(R)

    key_schedule = []
    W = []
    for i in range(4*R):
        if i < N:
            Wi = key[i*N:(i+1)*N]
        elif i >= N and i % N == 0:
            Wi = xor_buffers(xor_buffers(W[i-N], rot_word(sub_word(W[i-1]))), rcon[i // N])
        elif 6 < N <= i and i % N == 4:
            Wi = xor_buffers(W[i-N], sub_word(W[i-1]))
        else:
            Wi = xor_buffers(W[i-N], W[i-1])

        W.append(Wi)

        # This is incredibly hacky
        if (i+1) % N == 0:
            K = b''.join(W[i-4+1:i+1])
            key_schedule.append(K)

    return key_schedule


def aes_encrypt_block(input_block, key):
    N = len(key) // 4
    R = N + 7

    key_schedule = expand_key(key)

    for r in range(R):
        round_key = key_schedule[r]

        if r == 0:
            add_round_key(input_block, round_key)
        elif r < R - 1:
            sub_bytes(input_block)
            shift_rows(input_block)
            mix_columns(input_block)
            add_round_key(input_block, round_key)
        else:
            sub_bytes(input_block)
            shift_rows(input_block)
            add_round_key(input_block, round_key)

    return input_block


def aes_decrypt_block(input_block, key):
    N = len(key) // 4
    R = N + 7

    key_schedule = expand_key(key)[::-1]

    for r in range(R):
        round_key = key_schedule[r]

        if r == 0:
            add_round_key(input_block, round_key)
            inv_shift_rows(input_block)
            inv_sub_bytes(input_block)
        elif r < R - 1:
            add_round_key(input_block, round_key)
            inv_mix_columns(input_block)
            inv_shift_rows(input_block)
            inv_sub_bytes(input_block)
        else:
            add_round_key(input_block, round_key)

    return input_block


def aes_ecb(input_data, key, operation='encrypt'):
    key_bits = len(key)*8
    if key_bits not in [128, 192, 256]:
        raise ValueError('Wrong size key. Must be either 128, 192 or 256 bits')

    if operation == 'encrypt':
        aes_func = aes_encrypt_block
    elif operation == 'decrypt':
        aes_func = aes_decrypt_block
    else:
        raise ValueError('Invalid operation argument')

    input_data = bytearray(input_data)
    output_data = bytearray(len(input_data))
    for i in range(0, len(input_data), 16):
        block = input_data[i:i+16]
        aes_func(block, key)
        output_data[i:i+16] = block

    return output_data


if __name__ == '__main__':

    with open('7.txt', 'r') as f:
        ciphertext = base64.b64decode(f.read())

    key = b'YELLOW SUBMARINE'
    plaintext = aes_ecb(ciphertext, key, operation='decrypt')
    print('key:', key)
    print('plaintext:', plaintext.decode())
