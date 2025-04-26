#include "authed_entry.h"
#include <cassert>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <netinet/in.h>
#include <sodium/crypto_aead_chacha20poly1305.h>
#include <sodium/crypto_box.h>
#include <sodium/crypto_kx.h>
#include <sodium/crypto_pwhash.h>
#include <sodium/randombytes.h>
#include <sys/socket.h>
#include <unistd.h>

const size_t buffer_size = 4096;

int crypt_gen(int client_sock, unsigned char *client_pk,
              unsigned char *client_sk, unsigned char *client_rx,
              unsigned char *client_tx) {

  /* Generate the client's key pair */
  crypto_kx_keypair(client_pk, client_sk);

  std::cerr << "this is client_pk" << std::endl;

  for (int i = 0; i < crypto_kx_PUBLICKEYBYTES; ++i) {
    printf("%c", client_pk[i]);
  }

  std::cout << std::endl;

  send(client_sock, client_pk, crypto_kx_PUBLICKEYBYTES, 0);

  /* Prerequisite after this point: the server's public key must be known by the
   * client */

  /* Compute two shared keys using the server's public key and the client's
     secret key. client_rx will be used by the client to receive data from the
     server, client_tx will be used by the client to send data to the server. */

  unsigned char server_pk[crypto_kx_PUBLICKEYBYTES];

  int crypto_bytes_read =
      recv(client_sock, server_pk, crypto_kx_PUBLICKEYBYTES, 0);

  std::cout << "ON THE CLIENT cryptobytesread: " << crypto_bytes_read
            << std::endl;

  std::cerr << "this is server_pk" << std::endl;

  for (int i = 0; i < crypto_kx_PUBLICKEYBYTES; ++i) {
    printf("%c", server_pk[i]);
  }

  std::cout << std::endl;

  if (crypto_kx_client_session_keys(client_rx, client_tx, client_pk, client_sk,
                                    server_pk) != 0) {
    std::cerr << "BAILED SUS KEYS" << std::endl;
    return 1;
    /* Suspicious server public key, bail out */
  }

  std::cerr << "DIDNT BAIL WE HAVE VALID KEYSSS YAYAYYYYY" << std::endl;
  return 0;
}

int encrypt_buffer(unsigned char *client_tx, unsigned char *msg_box,
                   int message_len, unsigned char *ciphertext,
                   unsigned long long *ciphertext_len, int client_sock) {

  unsigned char nonce[crypto_aead_chacha20poly1305_NPUBBYTES];

  randombytes_buf(nonce, sizeof nonce);

  send(client_sock, nonce, crypto_aead_chacha20poly1305_NPUBBYTES, 0);

  std::cerr << "sent the nonce" << std::endl;

  crypto_aead_chacha20poly1305_encrypt(ciphertext, ciphertext_len, msg_box,
                                       message_len, NULL, 0, NULL, nonce,
                                       client_tx);

  std::cerr << "this is the ciphertext_len" << ciphertext_len << std::endl;

  std::cerr << "okay so i sent with client_tx which is " << client_tx
            << "and nonce was " << nonce << std::endl;

  return 0;
}

int send_credentials(int client_sock, unsigned char *client_tx,
                     std::string &pswd_tmp) {

  std::string username;
  std::string password;

  std::cout << "enter username:" << std::endl;
  std::cin >> username;
  std::cout << "enter password:" << std::endl;
  std::cin >> password;

  char hashed_password[crypto_pwhash_STRBYTES];

  if (crypto_pwhash_str(hashed_password, password.data(), password.length() + 1,
                        crypto_pwhash_OPSLIMIT_SENSITIVE,
                        crypto_pwhash_MEMLIMIT_SENSITIVE) != 0) {
    /* out of memory */

    std::cerr << "out of mem" << std::endl;
  }

  // encrypt the username and password and send it over to the server and wait
  // for a resposne

  unsigned char username_ciphertext[username.length() + 1 +
                                    crypto_aead_chacha20poly1305_ABYTES];
  unsigned long long username_ciphertext_len;

  unsigned char password_ciphertext[password.length() + 1 +
                                    crypto_aead_chacha20poly1305_ABYTES];

  unsigned long long password_ciphertext_len;

  if (encrypt_buffer(
          client_tx,
          static_cast<unsigned char *>(static_cast<void *>(username.data())),
          username.length() + 1, username_ciphertext, &username_ciphertext_len,
          client_sock)) {
    std::cerr << "couldn't encrypt error in encrypt_buffer" << std::endl;
  }

  if (encrypt_buffer(
          client_tx,
          static_cast<unsigned char *>(static_cast<void *>(hashed_password)),
          password.length() + 1, password_ciphertext, &password_ciphertext_len,
          client_sock)) {
    std::cerr << "couldn't encrypt error in encrypt_buffer" << std::endl;
  }

  int received_username = -1;

  while (received_username == -1) {
    send(client_sock, username_ciphertext, username_ciphertext_len,
         0); // username
    recv(client_sock, &received_username, sizeof(received_username), 0);
  }

  int received_password = -1;

  while (received_password == -1) {
    send(client_sock, password_ciphertext, password_ciphertext_len, 0);
    recv(client_sock, &received_password, sizeof(received_password), 0);
  }

  int auth_stat = -1;

  recv(client_sock, &auth_stat, sizeof(auth_stat), 0);

  if (auth_stat == -1) {
    std::cout << "you sir/madam are not authenticated." << std::endl;
    exit(-1);
  }

  pswd_tmp = password;

  // communications with the server are now authenticated to this point

  std::memset(password.data(), 0, password.size());
  std::memset(username.data(), 0, username.size());

  return 0;
}

int read_and_create(std::string &file_name) {

  std::ifstream file(file_name, std::ios::binary);
  // the file that is passed must be an already encrypted file done by another
  // func;

  if (!file) {
    std::cerr << "couldn't open the file" << std::endl;
    return -1;
  }

  while (file) {
    // process it
  }

  return 0;
}

int main() {

  const size_t buffer_size = 4096;

  int client_sock = socket(AF_INET, SOCK_STREAM, 0);
  sockaddr_in server_address;
  server_address.sin_family = AF_INET;
  server_address.sin_port = htons(8080);
  server_address.sin_addr.s_addr = INADDR_ANY;

  int conn_stat = connect(client_sock, (struct sockaddr *)&server_address,
                          sizeof(server_address));

  unsigned char client_pk[crypto_kx_PUBLICKEYBYTES],
      client_sk[crypto_kx_SECRETKEYBYTES];
  unsigned char client_rx[crypto_kx_SESSIONKEYBYTES],
      client_tx[crypto_kx_SESSIONKEYBYTES];

  if (crypt_gen(client_sock, client_pk, client_sk, client_rx, client_tx)) {
    std::cerr << "error generating keys :(" << std::endl;
    return 1;
  }

  for (int i = 0; i < crypto_kx_SESSIONKEYBYTES; ++i) {
    printf("%c", client_tx[i]);
  }

  std::cerr << std::endl;

  std::string pswd_tmp;

  if (send_credentials(client_sock, client_tx, pswd_tmp)) {
    std::cerr << "couldn't verify credentials" << std::endl;
  }

  Sender s = Sender(client_sock);

  unsigned char
      salt[crypto_pwhash_SALTBYTES]; // needs to be stored in the sqlite db.

  unsigned char key[crypto_box_SEEDBYTES];

  randombytes_buf(salt, sizeof salt);

  if (crypto_pwhash(key, sizeof key, pswd_tmp.data(), pswd_tmp.length(), salt,
                    crypto_pwhash_OPSLIMIT_INTERACTIVE,
                    crypto_pwhash_MEMLIMIT_INTERACTIVE,
                    crypto_pwhash_ALG_DEFAULT) != 0) {
    /* out of memory */
    std::cerr << "out of mem" << std::endl;
  }

  std::memset(pswd_tmp.data(), 0, pswd_tmp.size());

  s.set_key(key);

  std::cout << "enter file name to send to server" << std::endl;

  std::string file_name;

  std::cin >> file_name;

  while (std::cin.fail()) {
    std::cin.clear();
    std::cin.ignore();
    std::cin >> file_name;
  }

  int enc_stat = read_and_create(file_name);

  if (enc_stat != 0) {
    std::cerr << "error enc_stat was not 0. error in read_and_create"
              << std::endl;
  }

  // create an encrypted file here using a key derived from the user's
  // password. user auths into the server, then the password (client side) is
  // used to derive an encryption key to encrypt and decrypt the files.

  file_name.append(".enc");

  s.fill_and_send(file_name);
}
