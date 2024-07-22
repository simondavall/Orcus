/* validation.h */
extern bool checkFilepathLength(const char* filepath, const int maxLength);
extern bool checkPasswordLength(const char* password, const int minLength, const int maxLength);
extern bool checkFilenameValidChars(const char* filepath);
extern bool checkPasswordValidChars(const char* password);
extern bool checkValidFile(const char* filepath);
 
