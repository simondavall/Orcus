#include <stdio.h>
#include <stdbool.h>
#include <string.h>

const int MAX_FILEPATH_LENGTH = 128;

bool checkFilepathLength(char* filepath);

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
