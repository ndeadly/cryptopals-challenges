from set_1.challenge_2 import xor_buffers

# English letter frequency ration taken from
# https://en.wikipedia.org/wiki/Letter_frequency#Relative_frequencies_of_letters_in_the_English_language
letter_frequencies = {'a': 0.08167, 'b': 0.01492, 'c': 0.02782,
                      'd': 0.04253, 'e': 0.12702, 'f': 0.02228,
                      'g': 0.02015, 'h': 0.06094, 'i': 0.06966,
                      'j': 0.00153, 'k': 0.00772, 'l': 0.04025,
                      'm': 0.02406, 'n': 0.06749, 'o': 0.07507,
                      'p': 0.01929, 'q': 0.00095, 'r': 0.05987,
                      's': 0.06327, 't': 0.09056, 'u': 0.02758,
                      'v': 0.00978, 'w': 0.02360, 'x': 0.00150,
                      'y': 0.01974, 'z': 0.00074, ' ': 0.01027}

# Build a histogram for all 256 chars
reference_hist = [letter_frequencies[chr(i)] if chr(i) in letter_frequencies else 0.0 for i in range(256)]

'''
def mean(x):
    return sum(x) / len(x)


def std(x):
    return ((1/(len(x)-1)) * sum([(xi-mean(x))**2 for xi in x])) ** 0.5


def corr_coeff(x, y):
    n = len(x)
    s_x = std(x)
    s_y = std(y)
    r_xy = (sum(xi*yi for xi, yi in zip(x, y)) - n*mean(x)*mean(y)) / ((n-1)*s_x*s_y)
    return r_xy


def score_plaintext(plaintext):
    chars = plaintext.lower()
    total_chars = len(plaintext)
    hist = []

    for ch in range(256):
        char_count = chars.count(ch)
        hist.append(char_count / total_chars)

    try:
        score = abs(corr_coeff(hist, reference_hist))
    except:
        score = 0

    #print(hist)
    #print(score)
    return score
'''

'''
def score_plaintext(plaintext):
    chars = plaintext.lower()
    total_chars = len(plaintext)
    hist = []
    for letter in letter_frequencies.keys():
        letter_count = chars.count(ord(letter))
        hist.append(letter_count / total_chars)

    try:
        score = abs(corr_coeff(hist, letter_frequencies.values()))
    except:
        score = 0

    print(hist)
    print(score)
    return score
'''


common_chars = 'etaoin shrdlu'


def score_plaintext(plaintext):
    ''' This method is dumb, but it works ¯\_(ツ)_/¯ '''

    score = 0
    chars = plaintext.lower()
    for w, c in enumerate(common_chars[::-1]):
        score += chars.count(ord(c)) * (w+1)

    return score


def find_single_byte_xor_key(data):
    scores = []
    for i in range(256):
        key = i.to_bytes(1, 'little')
        decrypted = single_byte_repeating_xor(data, key)
        score = score_plaintext(decrypted)
        scores.append(score)

    key = scores.index(max(scores)).to_bytes(1, 'little')
    return key


def single_byte_repeating_xor(data, key):
    return xor_buffers(data, key*len(data))


if __name__ == '__main__':
    ciphertext = bytes.fromhex('1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736')

    key = find_single_byte_xor_key(ciphertext)
    plaintext = single_byte_repeating_xor(ciphertext, key)
    print('key:\t\t', key)
    print('plaintext:\t', plaintext.decode())
