#include <stdio.h>
#include <stdbool.h>
#include <string.h>

const int MAX_FILEPATH_LENGTH = 128;
const int MAX_PASSWORD_LENGTH = 20;
const int MIN_PASSWORD_LENGTH = 8;

bool checkFilepathLength(const char* filepath);
bool checkPasswordLength(const char* password);
bool checkFilenameValidChars(const char* filepvath);

int main(int argc, char* argv[]){

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
  int validCharsLength = strlen(validChars);
  int filepathLength = strlen(filepath);
  bool charValid = false;


  for (int i = 0; i < filepathLength; i++) {
    charValid = false;
    for (int j = 0; j < validCharsLength; j++) {
      if(filepath[i] == validChars[j]){
        charValid = true;
        break;
      }
    }

    if(!charValid){
      printf("Password contains invalid characters. The following characters are valid:\n\n\t");
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
