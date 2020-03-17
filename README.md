# FeistelCipher
Program to encrypt and decrypt using the Feistel Cipher. It has the option of one of three modes: ECB, CBC, or CTR.

## Getting Started
These instruction will help encrypt a plaintext and/or decrypt ciphertext using the Feistel cipher in ECB, CBC, or CTR mode.

## Prerequisite
* Python3

## Usage
### Arguments
* -h, --help
* -e, --encrypt
* -d, --decrypt
* -m, --mode
* -r, --rounds
* -b, --block
* -t, --text
* -i, --input
* -o, --output
* -k, --key
* -s, --silent

#### Cipher Operations
The program allows both the encryption and the decryption using the Feistel cipher.

##### Encrypt
The encryption operation (enabled by `-e`) takes in a plaintext and performs the encryption operation using the provided key and returns the ciphertext.
```
python3 -B feistel.py -e -i input.file -k foobar
```

##### Decrypt
Oppose to the encryption operation, the ciphertext encrypted using the Feistel cipher can be decrypted using `-d`. It takes a ciphertext and the key to return the decrypted plaintext.
```
python3 -B feistel.py -d -i input.file -k foobar
```

#### Input Methods
The program allows text or file methods for inputting the plaintext/ciphertext.
> Only one input method is allowed per operation.

##### Text (Command-line)
The plaintext can be inputted using the `-t` argument.
```
python3 -B feistel.py -e -t "this is my text" -k foobar
```
> Plaintext with spaces or special character must be wrapped in quotes.

> Decryption does not allow text input as ciphertext is outputted as bytes.

##### File
Larger plaintext/ciphertext might not be best passing via the command-line. Alternatively, the plaintext/ciphertext can be stored in a file and inputted by providing the filename with `-i`.
```
python3 -B feistel.py -e -i input.file -k foobar
```
> The input file must only contain the plaintext or ciphertext.

#### Encryption Key
A key must be provided for performing encryption/decryption. The key is a human readable string provided by using `-k`.
```
python3 -B feistel.py -e -i input.file -k foobar
```

#### Output Results to File
The `-o` argument allows the output of the program to be saved to a file.
```
python3 -B feistel.py -e -i input.file -k foobar -o output.file
```
> The plaintext/ciphertext is outputted as bytes thus using the appropriate file extention is crucial for the OS to recognize file types for reading.

#### Cryptographic Mode
The cryptographic mode can be configured using the `-m`. There are 3 modes that are accepted:
* ECB Mode (Electronic Codebook)
* CBC Mode (Cipher Block Chaining)
* CTR Mode (Counter)

> The mode must be passed as abbreviated lowercase formats: `ecb`, `cbc`, `ctr`.

> By default, the mode is set to ECB.

##### ECB Mode (Electronic Codebook)
```
python3 -B feistel.py -e -i input.file -k foobar -o output.file -m ecb
```

##### CBC Mode (Cipher Block Chaining)
```
python3 -B feistel.py -e -i input.file -k foobar -o output.file -m cbc
```

##### CTR Mode (Counter)
```
python3 -B feistel.py -e -i input.file -k foobar -o output.file -m ctr
```

#### Block Size
The block size of the cipher block can be modified using `-b`.
```
python3 -B feistel.py -e -i input.file -k foobar -o output.file -b 16
```
> By default, the block size is set to 256.

#### Rounds
The number of rounds that the cipher executes can be configured using the `-r`.
```
python3 -B feistel.py -e -i input.file -k foobar -o output.file -r 16
```
> By default, the number of rounds is set to 8.

#### Silent
The silent option, `-s`, suppresses output messages except for the plaintext/ciphertext. Ideal for IO redirection of the output.
```
python3 -B feistel.py -e -i input.file -k foobar -o output.file -s
```

## Author

**Gabriel Lee** - [ScrawnySquirrel](https://github.com/ScrawnySquirrel)
