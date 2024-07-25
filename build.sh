#!/bin/bash

mkdir build

SOC_LIB=src/orcus

gcc -c -g -o $SOC_LIB/validation.o $SOC_LIB/validation.c
gcc -c -g -o $SOC_LIB/encryption.o $SOC_LIB/encryption.c

gcc -o build/encrypt src/encrypt.c -lsodium $SOC_LIB/validation.o $SOC_LIB/encryption.o
gcc -o build/decrypt src/decrypt.c -lsodium $SOC_LIB/validation.o $SOC_LIB/encryption.o

