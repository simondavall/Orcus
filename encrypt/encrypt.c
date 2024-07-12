#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <sodium.h>

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

bool encryptFile(const char* filepath, const char* password){
  #define MESSAGE_PART1 (const unsigned char *) "Arbitrary data to encrypt"
  #define MESSAGE_PART1_LEN    25
  #define CIPHERTEXT_PART1_LEN MESSAGE_PART1_LEN + crypto_secretstream_xchacha20poly1305_ABYTES

  #define MESSAGE_PART2 (const unsigned char *) "split into"
  #define MESSAGE_PART2_LEN    10
  #define CIPHERTEXT_PART2_LEN MESSAGE_PART2_LEN + crypto_secretstream_xchacha20poly1305_ABYTES

  #define MESSAGE_PART3 (const unsigned char *) "three messages"
  #define MESSAGE_PART3_LEN    14
  #define CIPHERTEXT_PART3_LEN MESSAGE_PART3_LEN + crypto_secretstream_xchacha20poly1305_ABYTES

  crypto_secretstream_xchacha20poly1305_state state;
  unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
  unsigned char c1[CIPHERTEXT_PART1_LEN],
                c2[CIPHERTEXT_PART2_LEN],
                c3[CIPHERTEXT_PART3_LEN];
 
  /* Shared secret key required to encrypt/decrypt the stream */
  unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES];

  if(!GenerateSecretKey(key, sizeof key, password)){
    printf("Failed to generate secrity key.\n");
    return false;
  }

  /* Set up a new stream: initialize the state and create the header */
  crypto_secretstream_xchacha20poly1305_init_push(&state, header, key);

  /* Now, encrypt the first chunk. `c1` will contain an encrypted,
   * authenticated representation of `MESSAGE_PART1`. */
  crypto_secretstream_xchacha20poly1305_push
   (&state, c1, NULL, MESSAGE_PART1, MESSAGE_PART1_LEN, NULL, 0, 0);

  /* Encrypt the second chunk. `c2` will contain an encrypted, authenticated
   * representation of `MESSAGE_PART2`. */
  crypto_secretstream_xchacha20poly1305_push
   (&state, c2, NULL, MESSAGE_PART2, MESSAGE_PART2_LEN, NULL, 0, 0);

  /* Encrypt the last chunk, and store the ciphertext into `c3`.
   * Note the `TAG_FINAL` tag to indicate that this is the final chunk. */
  crypto_secretstream_xchacha20poly1305_push
   (&state, c3, NULL, MESSAGE_PART3, MESSAGE_PART3_LEN, NULL, 0,
    crypto_secretstream_xchacha20poly1305_TAG_FINAL);

  printf("Reached the end of the encryption.\n");
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
