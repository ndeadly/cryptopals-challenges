
def xor_buffers(buff1, buff2):
    return bytes([b1 ^ b2 for b1, b2 in zip(buff1, buff2)])


if __name__ == '__main__':
    input1 = bytes.fromhex('1c0111001f010100061a024b53535009181c')
    input2 = bytes.fromhex('686974207468652062756c6c277320657965')
    output = bytes.fromhex('746865206b696420646f6e277420706c6179')

    result = xor_buffers(input1, input2)
    print(result.hex())
    assert(result == output)
