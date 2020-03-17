#!/usr/bin/python3.7

import sys
import argparse
import time

import baseconversion as bc
import cryptography as cg

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
    parser.add_argument('-s', '--silent', help='suppress output messages', action='store_true')
    args = parser.parse_args()

    if args.text is not None and args.decrypt is True:
        parser.error("argument -d/--decrypt: not allowed with argument -t/--text")
        exit()

    if args.silent is False:
        start_time = time.time()

    # Input data
    bin_key = bc.string_to_binary(args.key)
    rnd = args.rounds
    txt = []
    if args.text is not None:
        byte_txt = bytes(args.text, 'utf-8')
        txt = [bc.byte_to_binary(byte_txt[i:i+args.block]) for i in range(0, len(byte_txt), args.block)]
    elif args.input is not None:
        with open(args.input, "rb") as infile:
            while True:
                data = infile.read(args.block)
                if not data:
                    break
                txt.append(bc.byte_to_binary(data))

    # Generate subkeys
    bin_subkeys = [ cg.right_shift(bin_key, block_num) for block_num in range(len(txt)) ]

    # Encryption/Decryption
    results = ""
    if args.encrypt is True:
        if "ecb" in args.mode:
            results =  cg.ecb_encrypt(txt,bin_subkeys,rnd)
        elif "cbc" in args.mode:
            results = cg.cbc_encrypt(txt,bin_subkeys,rnd)
        elif "ctr" in args.mode:
            results = cg.ctr_encrypt(txt,bin_subkeys,rnd)
    elif args.decrypt is True:
        if "ecb" in args.mode:
            results = cg.ecb_decrypt(txt,bin_subkeys,rnd)
        elif "cbc" in args.mode:
            results = cg.cbc_decrypt(txt,bin_subkeys,rnd)
        elif "ctr" in args.mode:
            results = cg.ctr_decrypt(txt,bin_subkeys,rnd)

    # Output data
    outfile = None
    if args.output is not None:
        outfile = open(args.output, "wb")
        for block in results:
            outfile.write(bc.binary_to_byte(block))
    else:
        outmsg = ""
        for block in results:
            sys.stdout.buffer.write(bc.binary_to_byte(block))


    if args.silent is False:
        print("--- %s seconds ---" % (time.time() - start_time))

if __name__ == "__main__":
    main(sys.argv[1:])
