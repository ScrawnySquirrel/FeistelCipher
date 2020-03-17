import multiprocessing
from itertools import repeat
import random
import math

import baseconversion as bc

def split_half(str):
    """
    Split a string in half and return tuple.

    str - the string to split
    """
    split_pairs = str[:len(str)//2], str[len(str)//2:]
    return split_pairs

def left_shift(key,shift):
    """
    Shift key string left and loopback the overflow bits.

    key - the key to shift
    shift - number of spaces to shift
    """
    if shift > len(key):
        shift = shift % len(key)
    return key[shift:] + key[:shift]

def right_shift(key,shift):
    """
    Shift key string right and loopback the overflow bits.

    key - the key to shift
    shift - number of spaces to shift
    """
    if shift > len(key):
        shift = shift % len(key)
    return key[-shift:] + key[:-shift]

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

def round_function(ri, key, round=1):
    """
    The Feistel round function.

    ri - the right-hand value
    key - the encryption key
    round - the nth round of the operation
    """
    max_size = int("1"*len(ri), 2)
    return bc.int_to_binary(pow(bc.binary_to_int(ri) * bc.binary_to_int(key), round) % max_size, len(ri))

def feistel_encrypt(pt_bin, key, rounds=2):
    """
    Perform Feistel cipher encryption.

    pt_bin - the plaintext binary
    key - the encryption key
    rounds - the number of rounds to run
    """
    enc_pairs = list(split_half(pt_bin))
    enc_key = proper_key(key, len(enc_pairs[0]))
    for i in range(1,rounds+1):
        enc_pairs[0],  enc_pairs[1] = enc_pairs[1], xor_compare(enc_pairs[0], round_function(enc_pairs[1], enc_key, i))
    return ''.join(enc_pairs)

def feistel_decrypt(ct_bin, key, rounds=2):
    """
    Perform Feistel cipher decryption.

    ct_bin - the ciphertext binary
    key - the encryption key
    rounds - the number of rounds to run
    """
    dec_pairs = list(split_half(ct_bin))
    dec_key = proper_key(key, len(dec_pairs[0]))
    for i in reversed(range(1, rounds+1)):
        dec_pairs[0],  dec_pairs[1] = xor_compare(dec_pairs[1], round_function(dec_pairs[0], dec_key, i)), dec_pairs[0]
    return ''.join(dec_pairs)

def ecb_encrypt(pt_bin_list, keys, rounds):
    """
    Perform Feistel encryption using ECB mode.

    pt_bin_list - list of plaintext blocks in binary
    keys - list of subkeys
    rounds - number of rounds to execute
    """
    enc_result = ""

    with multiprocessing.Pool() as p:
        enc_result = p.starmap(feistel_encrypt, zip(pt_bin_list, keys, repeat(rounds)))
    return enc_result

def ecb_decrypt(ct_bin_list, keys, rounds):
    """
    Perform Feistel decryption using ECB mode.

    ct_bin_list - list of ciphertext blocks in binary
    keys - list of subkeys
    rounds - number of rounds to execute
    """
    dec_result = ""

    with multiprocessing.Pool() as p:
        dec_result = p.starmap(feistel_decrypt, zip(ct_bin_list, keys, repeat(rounds)))
    return dec_result

def cbc_encrypt(pt_bin_list, keys, rounds):
    """
    Perform Feistel encyption using CBC mode.

    pt_bin_list - list of plaintext blocks in binary
    keys - list of subkeys
    rounds - number of rounds to execute
    """
    bsize = len(pt_bin_list[0])
    ivector = generate_random_binary(bsize) # Initialization Vector
    enc_result = []
    msg = pt_bin_list

    enc_result.append(feistel_encrypt(xor_compare(msg[0],ivector),keys[0],rounds))
    if len(msg) > 1:
        for i in range(1,len(msg)):
            enc_result.append(feistel_encrypt(xor_compare(msg[i], enc_result[i-1]),keys[i],rounds))
    enc_result.insert(0,ivector) # Store IV to the start of ciphertext
    return enc_result

def cbc_decrypt(ct_bin_list, keys, rounds):
    """
    Perform Feistel decryption using CBC mode.

    ct_bin_list - list of ciphertext blocks in binary
    keys - list of subkeys
    rounds - number of rounds to execute
    """
    ivector = ct_bin_list.pop(0)
    dec_result = []
    msg = ct_bin_list

    with multiprocessing.Pool() as p:
        x = p.starmap(feistel_decrypt, zip(msg, keys, repeat(rounds)))

    dec_result.append(xor_compare(x[0],ivector))
    if len(x) > 1:
        for i in range(1, len(x)):
            dec_result.append(xor_compare(x[i],msg[i-1]))

    return dec_result

def ctr_encrypt(pt_bin_list, keys, rounds):
    """
    Perform Feistel encyption using CTR mode.

    pt_bin_list - list of plaintext blocks in binary
    keys - list of subkeys
    rounds - number of rounds to execute
    """
    msg = pt_bin_list
    nonce = generate_random_binary(len(pt_bin_list[0])-8) # Initialization Vector
    counter = range(0,len(msg))
    enc_result = ""

    with multiprocessing.Pool() as p:
        enc_result = p.starmap(ctr_process, zip(msg, repeat(nonce), counter, keys, repeat(rounds)))

    enc_result.insert(0,nonce+"00000000") # Store padded IV to the start of ciphertext
    return enc_result

def ctr_decrypt(ct_bin_list, keys, rounds):
    """
    Perform Feistel decryption using CTR mode.

    ct_bin_list - list of ciphertext blocks in binary
    keys - list of subkeys
    rounds - number of rounds to execute
    """
    msg = ct_bin_list
    nonce = msg.pop(0)[:-8]
    counter = range(0,len(msg))
    dec_result = ""

    with multiprocessing.Pool() as p:
        dec_result = p.starmap(ctr_process, zip(msg, repeat(nonce), counter, keys, repeat(rounds)))

    return dec_result

def ctr_process(msg, nonce, cnt, key, rounds):
    """
    Perform encryption/decryption of a single block using CTR mode.

    msg - message block
    nonce - nonce
    cnt - increment counter
    key - encryption/decryption key
    rounds - number of rounds to execute
    """
    ivcount = nonce + bc.int_to_binary(cnt, 8)
    x = feistel_encrypt(ivcount,key,rounds)
    y = xor_compare(msg,x)
    return y
