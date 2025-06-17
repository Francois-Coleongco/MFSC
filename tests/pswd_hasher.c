#include <sodium/crypto_pwhash.h>
#include <string.h>
#include <stdio.h>

int main() {

  char *PASSWORD = "gourd";

  char hashed_password[crypto_pwhash_STRBYTES];

  if (crypto_pwhash_str(hashed_password, PASSWORD, strlen(PASSWORD),
                        crypto_pwhash_OPSLIMIT_SENSITIVE,
                        crypto_pwhash_MEMLIMIT_SENSITIVE) != 0) {
    /* out of memory */
  }

  if (crypto_pwhash_str_verify(hashed_password, PASSWORD, strlen(PASSWORD) + 1) !=
      0) { // we also include null byte
    /* wrong password */
  }

  printf("%s", hashed_password);
}
