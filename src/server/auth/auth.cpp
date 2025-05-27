#include <iostream>
#include <iterator>
#include <openssl/evp.h>
#include <ostream>
#include <sodium.h>
#include <sodium/crypto_pwhash.h>
#include <sqlite3.h>
#include <string>

int create_user(sqlite3 *DB, std::string &username, std::string &password) {

  sqlite3_stmt *stmt;

  const char *check_exists_query =
      "SELECT COUNT(*) FROM users WHERE username = ?;";

  if (sqlite3_prepare_v2(DB, check_exists_query, -1, &stmt, nullptr) !=
      SQLITE_OK) {
    std::cerr << "unable to prepare check_exists_query" << sqlite3_errmsg(DB)
              << std::endl;
  }

  sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_STATIC);

  if (sqlite3_step(stmt) == SQLITE_ROW) {
    int count = sqlite3_column_int(stmt, 0);
    if (count > 0) {
      std::cerr << "USER EXISTS" << std::endl;
      return 1;
    }
  }

  sqlite3_finalize(stmt);

  char hashed_password[crypto_pwhash_STRBYTES];

  const unsigned char *key =
      reinterpret_cast<const unsigned char *>(username.c_str());

  if (crypto_pwhash_str(hashed_password, password.c_str(), password.length(),
                        crypto_pwhash_OPSLIMIT_SENSITIVE,
                        crypto_pwhash_MEMLIMIT_SENSITIVE) != 0) {

    std::cout << "out of memory from crypto_pwhash_str inside create_user()"
              << std::endl;
    /* out of memory */
  }

  if (crypto_pwhash_str_verify(hashed_password, password.c_str(),
                               password.length()) != 0) {
    std::cerr << "wrong password bitch" << std::endl;
    return 3;
    /* wrong password */
  }

  std::cout << "successfully verified password" << std::endl;
;
  const char *create_user_query =
      "INSERT INTO users( username, hashed_pswd ) values( ?, ? );";

  if (sqlite3_prepare_v2(DB, create_user_query, -1, &stmt, nullptr) !=
      SQLITE_OK) {
    std::cerr << "unable to prepare create_user_query" << sqlite3_errmsg(DB)
              << std::endl;
  }

  std::cerr << "right before binds" << std::endl;

  std::cout << "last char of hashed_password: " << hashed_password[127]
            << std::endl;

  sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_STATIC);
  sqlite3_bind_text(stmt, 2, hashed_password, -1, SQLITE_STATIC);

  int res = sqlite3_step(stmt);

  std::cout << "thjios was res: " << res << std::endl;
  std::cout << sqlite3_errmsg(DB) << std::endl;

  sqlite3_finalize(stmt);

  std::fill(std::begin(hashed_password), std::end(hashed_password), '\0');
  std::fill(username.begin(), username.end(), '\0');
  std::fill(password.begin(), password.end(), '\0');

  return 0;
}

int login(sqlite3 *DB, char username[], size_t username_len, char password[],
          size_t password_len) {

  sqlite3_stmt *stmt;

  const char *retrieve_hashed_pswd =
      "SELECT hashed_pswd FROM users WHERE username = ?";

  std::cerr << "grabbed username was " << username << "\n ";
  std::cerr << "this was password " << password << "\n";
  std::cerr << "this was DB " << DB << "\n";

  char hash[crypto_pwhash_STRBYTES];

  std::cerr << "hashing password: " << password << "\n";
  if (crypto_pwhash_str(hash, (const char *)password, password_len,
                        crypto_pwhash_OPSLIMIT_SENSITIVE,
                        crypto_pwhash_MEMLIMIT_SENSITIVE) != 0) {
    /* out of memory */
  }

  std::cerr << "db  val: " << DB << "\n";


  if (sqlite3_prepare_v2(DB, retrieve_hashed_pswd, -1, &stmt, nullptr) !=
      SQLITE_OK) {
    std::cerr << "unable to prepare retrieve_hashed_pswd" << sqlite3_errmsg(DB)
              << std::endl;
    return 1;
  }

  sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);

  if (sqlite3_step(stmt) != SQLITE_ROW) {
    std::cerr << "no match in DATABASE" << std::endl;
    return 1;
  }

  std::cout << sqlite3_errmsg(DB) << std::endl;

  const unsigned char *db_password_hash = sqlite3_column_text(stmt, 0);

  if (crypto_pwhash_str_verify((const char *)db_password_hash, password,
                               password_len) != 0) {

    std::cerr << "this is password_len" << password_len << "\n";
    /* wrong password */
    std::cerr << "YOUUU SHALL NOTTTT PASSSSSSSSSSS" << std::endl;
    return 1;
  }

  std::cout << "SUCCESSFUL LOGIN YIPPIEEE" << std::endl;

  sodium_memzero(username, username_len);
  sodium_memzero(password, password_len);

  sqlite3_finalize(stmt);

  return 0;
}

int initialize_server(sqlite3 **DB) {

  int exit = 0;

  exit = sqlite3_open("term_chat_users.db", DB);

  if (exit != 0) {
    std::cerr << "couldn't open database" << std::endl;
    return 1;
  }

  return 0;
}
