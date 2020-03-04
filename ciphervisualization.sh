#!/bin/bash

if [[ -z $1 || -z $2 || -z $3 ]]; then
  echo "Missing positional arguments: "$0" <infile.bmp> <cipher-mode> <key>"
  exit
fi

infile=$(basename -- "$1")
extension="${infile##*.}"
filename="${infile%.*}"
ciphermode="$2"
key="$3"
outfile="${filename}${ciphermode}.${extension}"

# Quick debug
# echo "$infile"
# echo "$filename"
# echo "$extension"
# echo "$ciphermode"
# echo "$key"
# echo "$outfile"

openssl enc ${ciphermode} -k ${key} -in ${infile} -out ${filename}${ciphermode}.${extension}
dd if=${infile} of=${outfile} bs=1 count=54 conv=notrunc
