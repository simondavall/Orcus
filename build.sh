#!/bin/bash

SRC_DIR=src
SOC_LIB=$SRC_DIR/orcus


gcc -c -g -o $SOC_LIB/validation.o $SOC_LIB/validation.c
gcc -c -g -o $SOC_LIB/encryption.o $SOC_LIB/encryption.c

gcc -o build/encrypt $SRC_DIR/encrypt.c -lsodium $SOC_LIB/validation.o $SOC_LIB/encryption.o
gcc -o build/decrypt $SRC_DIR/decrypt.c -lsodium $SOC_LIB/validation.o $SOC_LIB/encryption.o

cp -f $SRC_DIR/testfile.txt build/testfile.txt

cd build
