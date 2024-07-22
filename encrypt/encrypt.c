#include <sodium/crypto_secretstream_xchacha20poly1305.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <sodium.h>
#include "socrates/encryption.h"
#include "socrates/validation.h"

const int MAX_FILEPATH_LENGTH = 128;
const int MAX_PASSWORD_LENGTH = 20;
const int MIN_PASSWORD_LENGTH = 8;

bool encryptFile(const char* filepath, const char* password);
bool GenerateSecretKey(unsigned char* const key, unsigned long long keyLen, const char* password);

int main(int argc, char* argv[]){

  if(sodium_init() == -1){
    printf("Encryption library failed to initialize.\n");
    return 1;
  }

  // check args
  if (argc < 3) {
    printf("Too few arguments. The following format should be used:\n");
    printf("\n\t encrypt <filename> <password>\n\n");
    return 1;
  }
  
  const char* filepath = argv[1];
  const char* password = argv[2];

  if (!checkFilepathLength(filepath, MAX_FILEPATH_LENGTH)){
    return 1;
  }

  if (!checkPasswordLength(password, MIN_PASSWORD_LENGTH, MAX_PASSWORD_LENGTH)){
    return 1;
  }

  if (!checkFilenameValidChars(filepath)){
    return 1;
  }

  if(!checkPasswordValidChars(password)){
    return 1;
  }

  if(!checkValidFile(filepath)){
    return 1;
  }

  if(!encryptFile(filepath, password)){
    return 1;
  }

  printf("File encrypted successfully.\n");

  return 0;
}

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
