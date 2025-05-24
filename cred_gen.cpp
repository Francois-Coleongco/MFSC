#include <iostream>
#include <sodium/crypto_pwhash.h>
#include <string.h>

int main() {
  std::string PASSWORD = "camel";
  char hashed_password[crypto_pwhash_STRBYTES];

  if (crypto_pwhash_str(hashed_password, PASSWORD.data(), PASSWORD.length(),
                        crypto_pwhash_OPSLIMIT_SENSITIVE,
                        crypto_pwhash_MEMLIMIT_SENSITIVE) != 0) {
    /* out of memory */
    return 1;
  }

  std::cout << hashed_password;
  
  
}
