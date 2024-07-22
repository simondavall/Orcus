/* encryption.h */
#include <sodium/crypto_secretstream_xchacha20poly1305.h>

bool encrypt(const char *targetFile, const char *sourceFile, const unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES]);


