#include <sodium/crypto_pwhash.h>
#include <sodium/crypto_secretstream_xchacha20poly1305.h>
#include <sodium/randombytes.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include "encryption.h"

const int CHUNK_SIZE = 4096;

bool encryptFile(const char *filepath, const char *password){

  /* Shared secret key required to encrypt/decrypt the stream */
  unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES];

  if(!GenerateSecretKey(key, sizeof key, password)){
    printf("Failed to generate secrity key.\n");
    return false;
  }

  char targetFilepath[strlen(filepath) + 4];
  strcpy(targetFilepath, filepath);
  strcat(targetFilepath, ".enc");

  // create or open/truncate the file to hold encrypted data 
  FILE *encryptedfptr;
  encryptedfptr = fopen(targetFilepath, "w");
  fclose(encryptedfptr);

  printf("Set up files and ready to encrypt");
  //return true;
  return encrypt(targetFilepath, filepath, key);
}

bool encrypt(const char *targetFile, const char *sourceFile, const unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES]){

  unsigned char buf_in[CHUNK_SIZE];
  unsigned char buf_out[CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES];
  unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
  crypto_secretstream_xchacha20poly1305_state state;
  FILE *fptr_s, *fptr_t;
  unsigned long long out_len;
  size_t rlen;
  int eof;
  unsigned char tag;

  fptr_s = fopen(sourceFile, "rb");
  fptr_t = fopen(targetFile, "wb");

  crypto_secretstream_xchacha20poly1305_init_push(&state, header, key);
  fwrite(header, 1, sizeof header, fptr_t);
  do{
    rlen = fread(buf_in, 1, sizeof buf_in, fptr_s);
    eof = feof(fptr_s);
    tag = eof ? crypto_secretstream_xchacha20poly1305_TAG_FINAL : 0;
    crypto_secretstream_xchacha20poly1305_push(&state, buf_out, &out_len, buf_in, rlen, NULL, 0, tag);
    fwrite(buf_out, 1, (size_t) out_len, fptr_t);
  } while(!eof);
  fclose(fptr_t);
  fclose(fptr_s);

  return true;
}

bool GenerateSecretKey(unsigned char* const out, unsigned long long outLen, const char* password){

  unsigned char salt[crypto_pwhash_SALTBYTES];

  randombytes_buf(salt, sizeof salt);

  if (crypto_pwhash
      (out, outLen, password, strlen(password), salt,
       crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE,
       crypto_pwhash_ALG_DEFAULT) != 0) {
      /* out of memory */
    printf("Out of memory.\n");
    return false;
  }

  return true;
}


