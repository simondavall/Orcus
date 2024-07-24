#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <sodium.h>
#include "encryption.h"

bool encrypt(const char *targetFile, const char *sourceFile, const unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES]);
bool decrypt(const char *targetFile, const char *sourceFile, const unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES]);
bool verifyEncryption(const char *encryptedFile, const char *originalFile, const char *password);
bool compareFiles(FILE *file1, FILE *file2);
bool GenerateSecretKey(unsigned char* key, const char* password);

const int CHUNK_SIZE = 4096;

bool encryptFile(const char *filepath, const char *password){

  unsigned char *key;

  if(!GenerateSecretKey(key, password)){
    printf("Failed to generate secrity key.\n");
    return false;
  }

  char targetFilepath[strlen(filepath) + 4];
  strcpy(targetFilepath, filepath);
  strcat(targetFilepath, ".encrypt");

  if(!encrypt(targetFilepath, filepath, key)){
    printf("Failed to encrypt file\n");
    remove(targetFilepath);
    return false;
  }

  if(!verifyEncryption(targetFilepath, filepath, password)){
    remove(targetFilepath);
    return false;
  }

  remove(filepath);
  rename(targetFilepath, filepath);

  return true;
}

bool encrypt(const char *targetFile, const char *sourceFile, const unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES]){

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

bool decryptFile(const char *filepath, const char *password){

  unsigned char *key;

  if(!GenerateSecretKey(key, password)){
    printf("Failed to generate secrity key.\n");
    return false;
  }

  char targetFilepath[strlen(filepath) + 4];
  strcpy(targetFilepath, filepath);
  strcat(targetFilepath, ".decrypt");

  if(!decrypt(targetFilepath, filepath, key)){
    // do something
    remove(targetFilepath);
    printf("Failed to decrypt the file");
    return false;
  }

  remove(filepath);
  rename(targetFilepath, filepath);

  return true;
}

bool decrypt(const char *targetFile, const char *sourceFile, const unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES]){

  unsigned char  buf_in[CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES];
  unsigned char  buf_out[CHUNK_SIZE];
  unsigned char  header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
  crypto_secretstream_xchacha20poly1305_state state;
  FILE          *fptr_t, *fptr_s;
  unsigned long long out_len;
  size_t         rlen;
  int            eof;
  int            ret = -1;
  unsigned char  tag;

  fptr_s = fopen(sourceFile, "rb");
  fptr_t = fopen(targetFile, "wb");
  fread(header, 1, sizeof header, fptr_s);
  if (crypto_secretstream_xchacha20poly1305_init_pull(&state, header, key) != 0) {
    printf("Incomplete header\n");
    goto ret; /* incomplete header */
  }
  do {
    rlen = fread(buf_in, 1, sizeof buf_in, fptr_s);
    eof = feof(fptr_s);
    if (crypto_secretstream_xchacha20poly1305_pull(&state, buf_out, &out_len, &tag,
                                                   buf_in, rlen, NULL, 0) != 0) {
      printf("Corrupted chunk\n");
      goto ret; /* corrupted chunk */
    }
    if (tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL) {
      if (! eof) {
        printf("End of stream reached before the enc of the file\n");
        goto ret; /* end of stream reached before the end of the file */
      }
    } else { /* not the final chunk yet */
      if (eof) {
        printf("End of file reached before the end of the stream\n");
        goto ret; /* end of file reached before the end of the stream */
      }
    }
    fwrite(buf_out, 1, (size_t) out_len, fptr_t);
  } while (! eof);

  ret = 0;
ret:
  fclose(fptr_t);
  fclose(fptr_s);

  return true;
}

bool verifyEncryption(const char *encryptedFile, const char *originalFile, const char *password){
  // decrypt the encrypted file and verify that is is the same as the original
  char tempFilepath[strlen(encryptedFile) + 4];
  strcpy(tempFilepath, encryptedFile);
  strcat(tempFilepath, ".ver");
  bool ret = true;

  unsigned char *key;
/*
  if(!GenerateSecretKey(key, password)){
    printf("Failed to generate security key during verification.\n");
    return false;
  }
/*
  if(!decrypt(tempFilepath, encryptedFile, key)){
    printf("Failed to decrypt file correctly during verification process\n");
    remove(tempFilepath);
    return false;
  }
/*
  // check decrypted file against original
  FILE *fptr_orig = fopen(originalFile, "r");
  FILE *fptr_temp = fopen(tempFilepath, "r");
  
  if (fptr_orig == NULL || fptr_temp == NULL){
    ret = false;
    printf("Verification failed\n");
    goto ret;
  }

  if(!compareFiles(fptr_orig, fptr_temp)){
    printf("Verifiacation failed\n");
    ret = false;
  }

ret:
  remove(tempFilepath);
  fclose(fptr_orig);
  fclose(fptr_temp);

*/
  return ret;
}

bool compareFiles(FILE *file1, FILE *file2){
  char ch1 = getc(file1);
  char ch2 = getc(file2);

  int error = 0, pos = 0, line = 1;

  while(ch1 != EOF && ch2 != EOF){
    if (ch1 != ch2){
      return false;
    }
    ch1 = getc(file1);
    ch2 = getc(file2);
  }

  return true;
}

bool GenerateSecretKey(unsigned char* key, const char* password){

  // todo: sdv need to rework this hardcoded feature. It needs to
  // stay constant for each user in order to recreate the key that
  // was used to encrypt the file for decryption.
  unsigned char salt[crypto_pwhash_SALTBYTES] = "123456789012345";
  //randombytes_buf(salt, sizeof salt);

  unsigned char out[crypto_box_SEEDBYTES];

  if (crypto_pwhash
      (out, sizeof out, password, strlen(password), salt,
       crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE,
       crypto_pwhash_ALG_DEFAULT) != 0) {
    printf("Failed to generate secure key\n");
    return false;
  }

  key = out;
  return true;
}


