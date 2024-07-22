/* validation.c */

#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include "validation.h"

bool checkValid(char* validChars, const char* toBeChecked, char* messageLabel);
 
// todo: need to return error codes rather than printf statements

bool checkFilepathLength(const char* filepath, const int maxLength){

  int strLength = strlen(filepath);

  if(strLength == 0){
    printf("<filepath> has zero length.\n");
    return false;
  }  
  
  if(strLength > maxLength){
    printf("<filepath> has too many characters. Max length: %d\n", maxLength);
    return false;
  }

  return true;
}

bool checkPasswordLength(const char* password, const int minLength, const int maxLength){

  int strLength = strlen(password);

  if(strLength < minLength){
    printf("<password> has too few characters. Min length: %d\n", minLength);
    return false;
  }  
  
  if(strLength > maxLength){
    printf("<password> has too many characters. Max length: %d\n", maxLength);
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
