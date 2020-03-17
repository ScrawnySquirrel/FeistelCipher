import binascii

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
