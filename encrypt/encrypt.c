#include <stdio.h>
#include <stdbool.h>
#include <string.h>

const int MAX_FILEPATH_LENGTH = 128;
const int MAX_PASSWORD_LENGTH = 20;
const int MIN_PASSWORD_LENGTH = 8;

bool checkFilepathLength(char* filepath);
bool checkPasswordLength(char* filepath);

int main(int argc, char* argv[]){

  printf("Started encryption\n");

  // check args
  if (argc < 3) {
    printf("Too few arguments. The following format should be used:\n");
    printf("\n\t encrypt <filename> <password>\n\n");
    return 1;
  }
  
  if (!checkFilepathLength(argv[1])){
    return 1;
  }

  if (!checkPasswordLength(argv[2])){
    return 1;
  }

  printf("File encrypted successfully.\n");

  return 0;
}

bool checkFilepathLength(char* filepath){

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

bool checkPasswordLength(char* password){

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

