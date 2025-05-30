#include <cstdio>
#include <cstring>
#include <iostream>
#include <iterator>
#include <openssl/evp.h>
#include <ostream>
#include <sodium.h>
#include <sodium/crypto_pwhash.h>
#include <sqlite3.h>
#include <string>

int initialize_server(sqlite3 **DB);
int login(sqlite3 *DB, char username[], size_t username_len, char password_hash[], size_t password_hash_len);
