#include <stdio.h>
#include <stdbool.h>

int main(void)
{
  int testsFailed = 0;
  int testCount = 0;

  printf("Start test run.....\n\n");

  while(testCount < 10){
    // put tests here
    if (testCount % 3 == 0){
      testsFailed++;
      printf("Test X : FAILED *****\n");
    } else {
      printf("Text X : PASSED\n");
    }
    testCount++;
  }

  if(testsFailed == 0){
    printf("\nAll tests PASSED successfully.\n");
  } else {
    printf("\n%d / %d tests failed.\n", testsFailed, testCount);
  }
  return 0;
}
