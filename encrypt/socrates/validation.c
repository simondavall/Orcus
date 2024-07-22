/* validation.c */

#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include "validation.h"

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


