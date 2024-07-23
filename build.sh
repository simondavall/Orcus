#!/bin/bash

gcc -c -g -o encrypt/socrates/validation.o encrypt/socrates/validation.c
gcc -c -g -o encrypt/socrates/encryption.o encrypt/socrates/encryption.c

gcc -o build/encrypt encrypt/encrypt.c -lsodium encrypt/socrates/validation.o encrypt/socrates/encryption.o
gcc -o build/decrypt encrypt/decrypt.c -lsodium encrypt/socrates/validation.o encrypt/socrates/encryption.o

cd build
