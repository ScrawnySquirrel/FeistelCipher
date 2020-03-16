#!/bin/bash

INPUT=${1}
EXT="${INPUT#*.}"
shift
ADDITIONAL_ARGS=${@}

# ECB Test
MODE="ecb"
echo -e "\033[35mMode: ${MODE}\033[0m"
echo -e "\033[96mEncryption...\033[0m"
python3 feistel.py -e -i ${INPUT} -k foobar -o enc_out-ecb.${EXT} -m ${MODE} ${ADDITIONAL_ARGS}
echo -e "\033[96mDecryption...\033[0m"
python3 feistel.py -d -i enc_out-ecb.${EXT} -k foobar -o dec_out-ecb.${EXT} -m ${MODE} ${ADDITIONAL_ARGS}
if [[ "$EXT" == "bmp" ]]; then
  echo -e "\033[96mAttach BMP header...\033[0m"
  dd if=${INPUT} of=enc_out-ecb.${EXT} bs=1 count=54 conv=notrunc
fi

echo ""

# CBC Test
MODE="cbc"
echo -e "\033[35mMode: ${MODE}\033[0m"
echo -e "\033[96mEncryption...\033[0m"
python3 feistel.py -e -i ${INPUT} -k foobar -o enc_out-cbc.${EXT} -m ${MODE} ${ADDITIONAL_ARGS}
echo -e "\033[96mDecryption...\033[0m"
python3 feistel.py -d -i enc_out-cbc.${EXT} -k foobar -o dec_out-cbc.${EXT} -m ${MODE} ${ADDITIONAL_ARGS}
if [[ "$EXT" == "bmp" ]]; then
  echo -e "\033[96mAttach BMP header...\033[0m"
  dd if=${INPUT} of=enc_out-cbc.${EXT} bs=1 count=54 conv=notrunc
fi

echo ""

# CTR Test
MODE="ctr"
echo -e "\033[35mMode: ${MODE}\033[0m"
echo -e "\033[96mEncryption...\033[0m"
python3 feistel.py -e -i ${INPUT} -k foobar -o enc_out-ctr.${EXT} -m ${MODE} ${ADDITIONAL_ARGS}
echo -e "\033[96mDecryption...\033[0m"
python3 feistel.py -d -i enc_out-ctr.${EXT} -k foobar -o dec_out-ctr.${EXT} -m ${MODE} ${ADDITIONAL_ARGS}
if [[ "$EXT" == "bmp" ]]; then
  echo -e "\033[96mAttach BMP header...\033[0m"
  dd if=${INPUT} of=enc_out-ctr.${EXT} bs=1 count=54 conv=notrunc
fi
