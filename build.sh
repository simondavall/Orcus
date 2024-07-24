#!/bin/bash
BASEDIR=$(cd $(dirname $0) && pwd)

SRC_DIR=encrypt
SOC_LIB=$SRC_DIR/socrates


gcc -c -g -o $SOC_LIB/validation.o $SOC_LIB/validation.c
gcc -c -g -o $SOC_LIB/encryption.o $SOC_LIB/encryption.c

gcc -o build/encrypt $SRC_DIR/encrypt.c -lsodium $SOC_LIB/validation.o $SOC_LIB/encryption.o
gcc -o build/decrypt $SRC_DIR/decrypt.c -lsodium $SOC_LIB/validation.o $SOC_LIB/encryption.o

cd build
