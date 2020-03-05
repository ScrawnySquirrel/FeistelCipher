# FeistelCipher

Program to encrypt and decrypt using the Feistel Cipher.

## Getting Started

These instruction will help encrypt a plaintext using the provided key and decrypt ciphertext using the Feistel cipher.

## Prerequisite

* Python3

## Usage
### Arguments
* -h, --help
* -e, --encrypt
* -d, --decrypt
* -c, --ciphermode
* -r, --rounds
* -t, --text
* -i, --input
* -o, --output
* -k, --key
* -a, --base64

#### Cipher Operations
The program allows both the encryption and the decryption using the Feistel cipher.

##### Encrypt
The encryption operation (enabled by `-e`) takes in a plaintex and performs the encryption operation using the provided key and returns the ciphertext.
```
```

##### Decrypt
Oppose to the encryption operation, the ciphertext encrypted using the Feistel cipher can be decrypted using `-d`. It takes a ciphertext and the key to return the decrypted plaintext.
```
```

#### Input Methods
The program allows multiple methods of inputting the plaintext/ciphertext.
> Only one input method is allowed per operation.

##### Text (Command-line)
The plaintext/ciphertext can be inputted using the `-t` argument.
```
```
> Plaintext/ciphertext with spaces or special character must be wrapped in quotes.

##### File
Larger plaintext/ciphertext might not be best passing via the command-line. Alternatively, the plaintext/ciphertext can be stored in a file and inputted by providing the filename with `-i`.
```
```
> The input file must only contain the plaintext or ciphertext.

#### Encryption Key
A key must be provided for performing encryption/decryption. The key is formatted to the plaintext for the cipher to execute properly. The key is a human readable string provided by the user using `-k`.
```
```

#### Output Results to File
The `-o` argument allows the output of the program to be saved to a text file.
```
```

#### Cryptographic Mode
The cryptographic mode can be configured using the `-c`. By default, it is set to ECB mode.
> Currently, only ECB mode is accepted

#### Rounds
The number of rounds that the cipher executes can be configured using the `-r`. By default the number of rounds is set to 8.

## Running the tests

## Author

**Gabriel Lee** - [ScrawnySquirrel](https://github.com/ScrawnySquirrel)
