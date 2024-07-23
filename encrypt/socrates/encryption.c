#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <sodium.h>
#include "encryption.h"

bool encrypt(const char *targetFile, const char *sourceFile, const unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES]);
bool decrypt(const char *targetFile, const char *sourceFile, const unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES]);
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

  return encrypt(targetFilepath, filepath, key);
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
  
  char backupFilepath[strlen(sourceFile) + 4];
  strcpy(backupFilepath, sourceFile);
  strcat(backupFilepath, ".bak");

  // todo: sdv move this to a proper place (maybe the calling function)
  // and rework. These functions all have return values that should be
  // used.
  remove(backupFilepath);
  rename(sourceFile, backupFilepath);
  rename(targetFile, sourceFile);

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

  return decrypt(targetFilepath, filepath, key);
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
        goto ret; /* incomplete header */
    }
    do {
        rlen = fread(buf_in, 1, sizeof buf_in, fptr_s);
        eof = feof(fptr_s);
        if (crypto_secretstream_xchacha20poly1305_pull(&state, buf_out, &out_len, &tag,
                                                       buf_in, rlen, NULL, 0) != 0) {
            goto ret; /* corrupted chunk */
        }
        if (tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL) {
            if (! eof) {
                goto ret; /* end of stream reached before the end of the file */
            }
        } else { /* not the final chunk yet */
            if (eof) {
                goto ret; /* end of file reached before the end of the stream */
            }
        }
        fwrite(buf_out, 1, (size_t) out_len, fptr_t);
    } while (! eof);

    ret = 0;
ret:
    fclose(fptr_t);
    fclose(fptr_s);

  // todo: sdv uncomment these lines to remove the backup file
  // that was created during encryption.
  // char backupFilepath[strlen(sourceFile) + 4];
  // strcpy(backupFilepath, sourceFile);
  // strcat(backupFilepath, ".bak");

  //remove(backupFilepath);
  remove(sourceFile);
  rename(targetFile, sourceFile);

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


