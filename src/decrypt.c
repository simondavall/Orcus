#include <stdio.h>
#include <stdbool.h>
#include <sodium.h>
#include "orcus/encryption.h"
#include "orcus/validation.h"

const int MAX_FILEPATH_LENGTH = 128;
const int MAX_PASSWORD_LENGTH = 20;
const int MIN_PASSWORD_LENGTH = 8;


int main(int argc, char* argv[]){

  if(sodium_init() == -1){
    printf("Encryption library failed to initialize.\n");
    return 1;
  }

  // check args
  if (argc < 3) {
    printf("Too few arguments. The following format should be used:\n");
    printf("\n\t decrypt <filename> <password>\n\n");
    return 1;
  }
  
  const char* filepath = argv[1];
  const char* password = argv[2];

  if (!validateFilePath(filepath, MAX_FILEPATH_LENGTH)){
    return 1;
  }

  if (!validatePassword(password, MIN_PASSWORD_LENGTH, MAX_PASSWORD_LENGTH)){
    return 1;
  }

  if(!decryptFile(filepath, password)){
    return 1;
  }

  printf("File decrypted successfully.\n");

  return 0;
}

