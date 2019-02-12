import base64


def hex_to_base64(hex_str):
    hex_data = bytes.fromhex(hex_str)
    return base64.b64encode(hex_data)


def main():
    input = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
    output = 'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'

    result = hex_to_base64(input)
    print(result.decode())
    assert(result.decode() == output)


if __name__ == '__main__':
    main()
