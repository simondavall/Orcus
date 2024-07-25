# Orcus

This is a linux based command-line file encryption / decryption tool.
It is a naive implementation used to show case the use of libsodium as
an encryption library.

##Installation

1. Clone the project locally.
2. Execute:
```./install.sh```
from within the Orcus base folder.
3. This places the executables in the usr/local/bin directory.
4. Make sure usr/local/bin is included in the PATH env variables.

##Usage

To encrypt a file:
``` encrypt <filepath> <password>```

To decrypt a file:
``` decrypt <filepath> <password>```

Note: Adding a space before the command will prevent it being added to the shell command history (if this option is set in your shell), and hence not expose the password in plain text.

##Builds

There is a build in the root dir ```./build.sh)``` which compiles encrypt.c and decrypt.c and places the executables, together with a testfile.txt, in a build folder.

Navigate to the build folder and test the executalbe as follows:

```./encrypt testtile.txt password```

this will encrypt the test text file.

```./decrypt testfile.txt password```

will decrypt the file back to plain text.

###Wish List / Issues
1. -Completed- ~~Remove backing up feature during encrypt process when it works.~~
2. What to do about forgotten password? Email? Master password?
3. Need to consider user salt value.
4. Add tests
