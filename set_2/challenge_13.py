import re
import secrets
from urllib.parse import parse_qsl, urlencode, unquote

from set_1.challenge_7 import aes_ecb
from set_2.challenge_9 import pkcs7_pad_plaintext

# Generate random key
secret_key = secrets.token_bytes(16)


def encrypt_profile(input_data):
    ciphertext = aes_ecb(pkcs7_pad_plaintext(input_data.encode('ascii'), 16), secret_key, operation='encrypt')
    return ciphertext


def decrypt_profile(input_data):
    plaintext = aes_ecb(input_data, secret_key, operation='decrypt')
    return parse_qs(plaintext[:-plaintext[-1]])


def parse_qs(query_string):
    return dict(parse_qsl(query_string.decode('charmap')))


def profile_for(email_addr):
    d = {'email': re.sub('[&=]', '', email_addr),
         'uid': 10,
         'role': 'user'}
    return encrypt_profile(unquote(urlencode(d)))


if __name__ == '__main__':
    profile1_encrypted = profile_for('admin@bar.com')
    profile2_encrypted = profile_for((b'AAAAAAAAAAadmin' + bytes([0xb]*11)).decode('utf-8'))
    admin_profile = decrypt_profile(profile1_encrypted[:-16] + profile2_encrypted[16:32])
    print(admin_profile)
