#!/usr/bin/python3.7

import sys
import argparse
import binascii

def main(argv):
    # Define script description and the arugment list
    parser = argparse.ArgumentParser(description='Encrypt and decrypt Feistel Cipher.')
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('-e', '--encrypt', help='encrypt a plaintext', action='store_true')
    mode.add_argument('-d', '--decrypt', help='decrypt a ciphertext', action='store_true')
    parser.add_argument('-c', '--ciphermode', help='encryption mode', default="ECB")
    parser.add_argument('-r', '--rounds', help='number of rounds to run', type=int, default=8)
    parser.add_argument('-t', '--text', help='the plaintext to encrypt')
    parser.add_argument('-i', '--input', help='name of the input file')
    parser.add_argument('-o', '--output', help='name of the output file')
    parser.add_argument('-k', '--key', help='the decryption key')
    # parser.add_argument('-f', '--function', help='function to use for cipher', default="")
    args = parser.parse_args()

    if args.text is not None:
        txt = args.text
    elif args.input is not None:
        txt = open(args.input, "r").read()

    if args.encrypt is True:
        ct = feistel_encrypt(string_to_binary(txt), args.rounds)
        print("cip: {}".format(ct))
        # print("xxx: {}".format(ct))
        # print("Orig: {}".format(txt))
        print("Bin: {}".format(string_to_binary(txt)))
        # print("Str: {}".format(binary_to_string(string_to_binary(txt))))
        # print("new: {}".format(binary_to_string(ct)))

    elif args.decrypt is True:
        print(binary_to_string(feistel_decrypt(txt, args.rounds)))


def split_half(str):
    split_pairs = str[:len(str)//2], str[len(str)//2:]
    return split_pairs

def string_to_binary(str):
    """
    Return a string converted binary.

    str - the string to convert
    """
    return bin(int(binascii.hexlify(str.encode()), 16))[2:].zfill(8*len(str))

def binary_to_string(bnry):
    """
    Return a binary converted string.

    bnry - the binary to convert
    """
    return binascii.unhexlify('%x' % int(bnry, 2)).decode()

def binary_to_hex(bnry):
    """
    Return a binary converted hex.

    bnry - the binary to convert
    """
    return hex(int(bnry, 2))[2:]

def hex_to_binary(hexa, nbits = 0):
    """
    Return a hex converted binary.

    hexa - the hex to convert
    nbits - number of bits for padding
    """
    return bin(int(hexa, 16))[2:].zfill(nbits)

def binary_to_int(bnry):
    """
    Return a binary converted integer.

    bnry - the binary to convert
    """
    return int(bnry, 2)

def int_to_binary(inte, nbits = 0):
    """
    Return a integer converted binary.

    hexa - the integer to convert
    nbits - number of bits for padding
    """
    return bin(inte)[2:].zfill(nbits)

def xor_compare(bin1, bin2):
    """
    Return an XOR comparison of two binary strings.

    bin1, bin2 - the binaries to compare
    """
    return '{0:0{1}b}'.format(int(bin1,2) ^ int(bin2, 2), len(bin1))

def feistel_encrypt(pt_bin, rounds):
    enc_pairs = list(split_half(pt_bin))
    print("{}".format(enc_pairs))
    for i in range(rounds):
        # enc_pairs[0],  enc_pairs[1] = enc_pairs[1], xor_compare(enc_pairs[0], enc_pairs[1])
        enc_pairs[0],  enc_pairs[1] = enc_pairs[1], xor_compare(enc_pairs[0], enc_pairs[1])
        print(enc_pairs)
    return ''.join(enc_pairs)
    # return bin(int(''.join(enc_pairs).encode(), 2))[2:]
    # return bin(int(binascii.hexlify(''.join(enc_pairs)), 16))[2:]

def feistel_decrypt(ct_bin, rounds):
    dec_pairs = list(split_half(ct_bin))
    for i in range(rounds):
        dec_pairs[0],  dec_pairs[1] = xor_compare(dec_pairs[0], dec_pairs[1]), dec_pairs[0]
        print(dec_pairs)
    return ''.join(dec_pairs)

if __name__ == "__main__":
    main(sys.argv[1:])
