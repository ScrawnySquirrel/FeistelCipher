#!/usr/bin/python3.7

import sys
import argparse
import binascii
import math
import multiprocessing
from itertools import repeat
import random

def main(argv):
    # Define script description and the arugment list
    parser = argparse.ArgumentParser(description='Encrypt and decrypt Feistel Cipher.')
    proccess = parser.add_mutually_exclusive_group(required=True)
    proccess.add_argument('-e', '--encrypt', help='encrypt a plaintext', action='store_true')
    proccess.add_argument('-d', '--decrypt', help='decrypt a ciphertext', action='store_true')
    parser.add_argument('-m', '--mode', help='encryption mode', default="ecb", choices=['ecb', 'cbc', 'ctr'])
    parser.add_argument('-r', '--rounds', help='number of rounds to run', type=int, default=8)
    parser.add_argument('-b', '--block', help='block size for cipher', type=int, default=256)
    inputmethod = parser.add_mutually_exclusive_group(required=True)
    inputmethod.add_argument('-t', '--text', help='plaintext to encrypt')
    inputmethod.add_argument('-i', '--input', help='name of the input file')
    parser.add_argument('-o', '--output', help='name of the output file')
    parser.add_argument('-k', '--key', help='encryption key', required=True)
    args = parser.parse_args()

    if args.text is not None and args.decrypt is True:
        parser.error("argument -d/--decrypt: not allowed with argument -t/--text")
        exit()

    # Input data
    bin_key = string_to_binary(args.key)
    rnd = args.rounds
    txt = []
    if args.text is not None:
        byte_txt = bytes(args.text, 'utf-8')
        txt = [byte_to_binary(byte_txt[i:i+args.block]) for i in range(0, len(byte_txt), args.block)]
    elif args.input is not None:
        with open(args.input, "rb") as infile:
            while True:
                data = infile.read(args.block)
                if not data:
                    break
                txt.append(byte_to_binary(data))

    # Encryption/Decryption
    results = ""
    if args.encrypt is True:
        if "ecb" in args.mode:
            with multiprocessing.Pool() as p:
                results = p.starmap(ecb_encrypt, zip(txt, repeat(bin_key), repeat(rnd)))
        elif "cbc" in args.mode:
            print("CBC Mode")
            results = cbc_encrypt(txt,bin_key,rnd)
        elif "ctr" in args.mode:
            print("CTR Mode")
    elif args.decrypt is True:
        if "ecb" in args.mode:
            with multiprocessing.Pool() as p:
                results = p.starmap(ecb_decrypt, zip(txt, repeat(bin_key), repeat(rnd)))
        elif "cbc" in args.mode:
            print("CBC Mode")
        elif "ctr" in args.mode:
            print("CTR Mode")

    # Output data
    outfile = None
    if args.output is not None:
        outfile = open(args.output, "wb")
        for block in results:
            output_fp(binary_to_byte(block), outfile)
    else:
        outmsg = ""
        for block in results:
            sys.stdout.buffer.write(binary_to_byte(block))

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
        ofile.write(msg)
        if fp_out is True:
            print(msg)
    return

def split_half(str):
    """
    Split a string in half and return tuple.

    str - the string to split
    """
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

def byte_to_binary(byt):
    """
    Return a byte converted binary.

    byt - the byte to convert
    """
    return int_to_binary(int.from_bytes(byt, byteorder='big'), len(byt)*8)

def binary_to_byte(bin):
    """
    Return a binary converted byte.

    bin - the binary to convert
    """
    return int(bin, 2).to_bytes(len(bin) // 8, byteorder='big')

def xor_compare(bin1, bin2):
    """
    Return an XOR comparison of two binary strings.
    The XOR'd binary string is padded to the first string.

    bin1, bin2 - the binaries to compare
    """
    return '{0:0{1}b}'.format(int(bin1,2) ^ int(proper_key(bin2, len(bin1)), 2), len(bin1))

def proper_key(key, klen):
    """
    Format the provided key to specific length.

    key - the base encryption key
    klen - the desired key length
    """
    ckey = ""
    if len(key) < klen:
        lmulti = math.floor(klen/len(key))
        lmod = klen % len(key)
        ckey = key * int(lmulti) + key[:lmod]
    elif len(key) > klen:
        ckey = key[:klen]
    else:
        ckey = key
    return ckey

def generate_random_binary(length):
    """
    Return a randomly generated binary string of size length.

    length - the length of the binary string to generate
    """
    key = [str(random.randint(0,1)) for x in range(length)]
    return "".join(key)

def feistel_function(ri, key, round=1):
    """
    The Feistel round function.

    ri - the right-hand value
    key - the encryption key
    round - the nth round of the operation
    """
    max_size = int("1"*len(ri), 2)
    return int_to_binary(pow(binary_to_int(ri) * binary_to_int(key), round) % max_size, len(ri))

def ecb_encrypt(pt_bin, key, rounds):
    """
    Perform Feistel cipher encryption.

    pt_bin - the plaintext binary
    key - the encryption key
    rounds - the number of rounds to run
    """
    enc_pairs = list(split_half(pt_bin))
    enc_key = proper_key(key, len(enc_pairs[0]))
    for i in range(1,rounds+1):
        enc_pairs[0],  enc_pairs[1] = enc_pairs[1], xor_compare(enc_pairs[0], feistel_function(enc_pairs[1], enc_key, i))
    return ''.join(enc_pairs)

def ecb_decrypt(ct_bin, key, rounds):
    """
    Perform Feistel cipher decryption.

    ct_bin - the ciphertext binary
    key - the encryption key
    rounds - the number of rounds to run
    """
    dec_pairs = list(split_half(ct_bin))
    dec_key = proper_key(key, len(dec_pairs[0]))
    for i in reversed(range(1, rounds+1)):
        dec_pairs[0],  dec_pairs[1] = xor_compare(dec_pairs[1], feistel_function(dec_pairs[0], dec_key, i)), dec_pairs[0]
    return ''.join(dec_pairs)

def cbc_encrypt(pt_bin_list, key, rounds):
    ivector = generate_random_binary(len(pt_bin_list[0])) # Initialization Vector
    enc_result = []
    msg = []

    for i in range(1, rounds+1):
        if i is 1:
            msg = pt_bin_list
        else:
            msg = enc_result.copy()
            enc_result.clear()
        ctext = ""
        ctext = feistel_function(xor_compare(ivector,msg[0]),key,i)
        enc_result.append(ctext)
        for j in range(1,len(msg)):
            ctext = feistel_function(xor_compare(enc_result[j-1],msg[j]),key,i)
            enc_result.append(ctext)
    return enc_result

def cbc_decrypt(ct_bin, key, rounds):
    return

if __name__ == "__main__":
    main(sys.argv[1:])
