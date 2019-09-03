import json


def read(json_file):
    with open(json_file) as f:
        data = json.load(f)

    return data


def Berlekamp_Massey_Algorithm(input_seq):
    # L is linear complexity, c is connection polynomial
    # Setup

    # create input sequence
    seq = []
    for inp in input_seq:
        seq.append(int(inp))

    n = len(seq)  # length of input sequence

    b = [0 for x in range(0, n)]  # array of 0s
    c = [0 for x in range(0, n)]  # array of 0s

    # Initialise
    c[0] = b[0] = 1  # set c[0] and b[0] to be 1
    L = 0
    N = 0  # to iterate through
    l = 1

    while N < n:  # from N to n-1
        # d is discrepancy
        d = 0
        for j in range(0, L + 1):
            d ^= (seq[N - j] & c[j])
        d %= 2

        if d == 1:
            t = c

            c2 = []
            for j in range(0, n):
                b2 = [0 for x in range(0, l)] + b
                c2.append(c[j] ^ b2[j])
            c = c2

            if L <= (N / 2):
                L = N + 1 - L
                l = 1
                b = t
            else:
                l += 1
        else:
            l += 1
        N += 1

    poly = []
    for x, e in enumerate(c):
        if e != 0:
            if x == 0:
                poly.append(1)
            else:
                poly.append(x)

    poly.reverse()

    taps = poly.copy()
    for index, t in enumerate(taps):
        taps[index] = t - 1
        if (t - 1 == 0):
            taps.remove(taps[index])

    polynomial = ''
    for index, p in enumerate(poly):
        if (index == len(poly) - 1):
            polynomial += str(p)
        else:
            polynomial += 'x^' + str(p) + "+"

    return (polynomial, taps)


def LFSR_keystream_generator(ciphertext, seed, taps):
    # generate key till key length == ciphertext length
    full_keystream = seed
    current_sequence = seed

    seed_length = len(seed)
    bits_index = []
    for i in taps:
        bits_index.append(seed_length - 1 - i)

    while len(full_keystream) < len(ciphertext):
        sum = 0
        for i in bits_index:
            sum += int(current_sequence[i])

        if (sum % 2 == 0):  # if sum is not odd, XOR gives 0
            bit = 0
        else:
            bit = 1  # else it gives 1

        full_keystream += str(bit)  # add bit to keystream
        current_sequence += str(bit)  # add bit to sequence
        current_sequence = current_sequence[1:]  # remove last bit to get new sequence

    return full_keystream


def xor(binary1, binary2):
    new_binary = ""
    for i, val in enumerate(binary1):
        new_binary += str((int(binary1[i])) ^ (int(binary2[i])))

    return new_binary


def to_plain_text(binary):
    plain_text = ""
    while binary != "":
        letter = binary[:8]
        plain_text += chr(int(letter, 2))
        binary = binary[8:]

    return plain_text


if __name__ == '__main__':
    data = read('input.json')
    print('Input data:', end='\n')
    print(data)
    print()

    input_seq = data['keyFragment']
    seed = data['lfsr']['seed']
    cipher_text_hexadecimal = data['cipherText']
    cipher_text_binary = bin(int(cipher_text_hexadecimal, 16))[2:]
    cipher_text_binary = str(cipher_text_binary)

    # Question 5: Obtain Feedback Polynomial
    print('Question 5 ' + '--' * 50)
    polynomial, taps = Berlekamp_Massey_Algorithm(input_seq)
    print('Polynomial is:', polynomial)
    print('Taps are:', taps)
    data['lfsr']['taps'] = taps
    print()

    # Question 6: Generate full keystream
    print('Question 6 ' + '--' * 50)
    full_keystream = LFSR_keystream_generator(cipher_text_binary, seed, taps)
    print('Full keystream (binary):', full_keystream)
    data['key'] = hex(int(full_keystream, 2))[2:]
    print('Full keystream (hex):', data['key'])
    print('KeyFragment is part of keystream:', input_seq in full_keystream)  # check if keyFragment part of key stream
    print()

    # Question 7: Decrypt and decode
    print('Question 7 ' + '--' * 50)
    print('CipherText', cipher_text_binary)
    decrypted_code = xor(full_keystream, cipher_text_binary)
    print('Decrypted code', decrypted_code)
    data['plainText'] = to_plain_text(decrypted_code)
    print('PlainText is:', data['plainText'])
    print()

    # Final output data
    print('Final json output ' + '--' * 50)
    print(data)

    with open('output.json', 'w') as outfile:
        json.dump(data, outfile)
