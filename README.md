# Socrates-C

Build

There is a local build at encrypt/b.sh (execute: ./b.sh) which compiles the encrypt.c file to encrypt in place
To execute this run 
```./encrypt```
in the encrypt dir.

There is a main build in the root dir (execute: ./build.sh) which compiles the encrypt.c file to the build dir
```./encrypt```
in the build dir to execute.

Testing
To test the local version of encrypt function:
1. Navigate to Socrates-C/encrypt
2. Build using ./b.sh
3. Run using ./encrypt_test textfile.txt password

To test the main build
1. Navigate to Socrates_C
2. Build using ./build.sh
3. Navigate to /build folder
4. Run using ./encrypt textfile.txt password

