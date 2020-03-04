#!/usr/bin/python3.7

import sys
import argparse
import binascii
import math

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
    parser.add_argument('-k', '--key', help='the decryption key', required=True)
    args = parser.parse_args()

    if args.text is not None:
        txt = args.text
    elif args.input is not None:
        txt = open(args.input, "r" if args.encrypt else "rb").read()

    out_file = None
    if args.output is not None:
        out_file = open(args.output, "wb" if args.encrypt else "w")

    mylist = []
    if args.encrypt is True:
        ct = feistel_encrypt(string_to_binary(txt), string_to_binary(args.key), args.rounds)
        output_fp(binary_to_hex(ct), out_file)
    elif args.decrypt is True:
        pt = feistel_decrypt(hex_to_binary(txt.rstrip()), string_to_binary(args.key), args.rounds)
        output_fp(binary_to_string(pt), out_file)

def output_fp(msg, ofile = None, fp_out = False):
    """
    Print to standard out or to file.

    msg - the messsage to output
    ofile - file to output
    fp_out - output to both
    """
    if ofile is None:
        print(msg)
    else:
        ofile.write(msg + "\n")
        if fp_out is True:
            print(msg)
    return

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

def proper_key(key, klen):
    ckey = "" # Cipher key
    if len(key) < klen:
        lmulti = math.floor(klen/len(key))
        lmod = klen % len(key)
        ckey = key * int(lmulti) + key[:lmod]
    elif len(key) > klen:
        ckey = key[:klen]
    else:
        ckey = key
    return ckey

def feistel_function(ri, key, round):
    max_size = int("1"*len(ri), 2)
    return int_to_binary(pow(binary_to_int(ri) * binary_to_int(key), round) % max_size, len(ri))


def feistel_encrypt(pt_bin, key, rounds):
    enc_pairs = list(split_half(pt_bin))
    enc_key = proper_key(key, len(enc_pairs[0]))
    for i in range(1,rounds+1):
        enc_pairs[0],  enc_pairs[1] = enc_pairs[1], xor_compare(enc_pairs[0], feistel_function(enc_pairs[1], enc_key, i))
    return ''.join(enc_pairs)

def feistel_decrypt(ct_bin, key, rounds):
    dec_pairs = list(split_half(ct_bin))
    dec_key = proper_key(key, len(dec_pairs[0]))
    for i in reversed(range(1, rounds+1)):
        dec_pairs[0],  dec_pairs[1] = xor_compare(dec_pairs[1], feistel_function(dec_pairs[0], dec_key, i)), dec_pairs[0]
    return ''.join(dec_pairs)

if __name__ == "__main__":
    main(sys.argv[1:])
