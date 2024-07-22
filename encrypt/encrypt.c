#include <sodium/crypto_secretstream_xchacha20poly1305.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <sodium.h>

const int CHUNK_SIZE = 4096;

const int MAX_FILEPATH_LENGTH = 128;
const int MAX_PASSWORD_LENGTH = 20;
const int MIN_PASSWORD_LENGTH = 8;

bool checkFilepathLength(const char* filepath);
bool checkPasswordLength(const char* password);
bool checkFilenameValidChars(const char* filepvath);
bool checkPasswordValidChars(const char* password);
bool checkValid(char* validChars, const char* toBeChecked, char* messageLabel);
bool checkValidFile(const char* filepath);
bool encryptFile(const char* filepath, const char* password);
static bool encrypt(const char *targetFile, const char *sourceFile, const unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES]);
bool GenerateSecretKey(unsigned char* const key, unsigned long long keyLen, const char* password);
void ReadBytes(char *bytesRead, int numBytesRead, FILE *file, const int length);

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

  if (!checkFilepathLength(filepath)){
    return 1;
  }

  if (!checkPasswordLength(password)){
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

  //todo sdv all tests passed so now encrypt the file.
  //https://stackoverflow.com/questions/7622617/simply-encrypt-a-string-in-c
  //have a look at this link
//todo sdv change the password into a secret key and zero the password before sending
  if(!encryptFile(filepath, password)){
    return 1;
  }

  printf("File encrypted successfully.\n");

  return 0;
}

bool checkFilepathLength(const char* filepath){

  int strLength = strlen(filepath);

  if(strLength == 0){
    printf("<filepath> has zero length.\n");
    return false;
  }  
  
  if(strLength > MAX_FILEPATH_LENGTH){
    printf("<filepath> has too many characters. Max length: %d\n", MAX_FILEPATH_LENGTH);
    return false;
  }

  return true;
}

bool checkPasswordLength(const char* password){

  int strLength = strlen(password);

  if(strLength < MIN_PASSWORD_LENGTH){
    printf("<password> has too few characters. Min length: %d\n", MIN_PASSWORD_LENGTH);
    return false;
  }  
  
  if(strLength > MAX_PASSWORD_LENGTH){
    printf("<password> has too many characters. Max length: %d\n", MAX_PASSWORD_LENGTH);
    return false;
  }

  return true;
}


bool checkFilenameValidChars(const char* filepath){

  char validChars[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890()-./:[]_~";

  return checkValid(validChars, filepath, "<filepath>");
}

bool checkPasswordValidChars(const char* password){

  char excludeChars[] = "\"\\ '`";
  int excludeCharsLength = strlen(excludeChars);

  int minChar = 32;
  int maxChar = 127;

  char buffer[maxChar];

  int idx = 0;
  bool isValidChar = true;

  for (int i = minChar; i < maxChar; i++) {
    for(int j = 0; j < excludeCharsLength; j++){
      if(i == (int)excludeChars[j]){
        isValidChar = false;
        break;
      }
    }
    if(isValidChar){
      buffer[idx] = (char)i;
      idx++;
    }
    isValidChar = true;
  }

  buffer[idx] = '\0';

  char validChars[idx];
  strcpy(validChars, buffer);

  return checkValid(validChars, password, "<password>");
}


bool checkValid(char* validChars, const char* toBeChecked, char* messageLabel){
  int stringLength = strlen(toBeChecked);
  int validCharsLength = strlen(validChars);

  bool charValid = false;

  for (int i = 0; i < stringLength; i++) {
    charValid = false;
    for (int j = 0; j < validCharsLength; j++) {
      if(toBeChecked[i] == validChars[j]){
        charValid = true;
        break;
      }
    }

    if(!charValid){
      printf("%s contains invalid characters. The following characters are valid:\n\n\t", messageLabel);
      int charsPerLine = 30;
      int idx = 0;
      for (int i = 0; i < validCharsLength; i++) {
        if(idx == charsPerLine){
          idx = 0;
          printf("\n\t");
        }
        printf("%c ", validChars[i]);
        idx++;
      }
      printf("\n\n");
      return false;
    }
  }

  return true;
}

bool checkValidFile(const char* filepath){
  // check that opening the file returns a valid file pointer
  FILE *fptr;
  fptr = fopen(filepath, "r");
  if(fptr == NULL){
    printf("Invalid file path. File not found.\n");
    return false;
  }
  return true;
}

static bool 
encrypt(const char *targetFile, const char *sourceFile, const unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES]){

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
