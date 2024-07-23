/* encryption.h */
#include <sodium/crypto_secretstream_xchacha20poly1305.h>

extern bool encryptFile(const char *filepath, const char *password);

