#include "authed_entry/authed_entry.h"
#include "../encryption_utils/encryption_utils.h"
#include <array>
#include <cassert>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <netinet/in.h>
#include <sodium/crypto_aead_chacha20poly1305.h>
#include <sodium/crypto_box.h>
#include <sodium/crypto_kx.h>
#include <sodium/crypto_pwhash.h>
#include <sodium/crypto_secretstream_xchacha20poly1305.h>
#include <sodium/randombytes.h>
#include <sodium/utils.h>
#include <sys/socket.h>
#include <unistd.h>

// intentions
const int ACK_SUC = 0;
const int ACK_FAIL = -1;

const int CONFUSION = -420;
const int READ_FROM_FILESYSTEM = 1;
const int WRITE_TO_FILESYSTEM = 2;

template <typename T> void get_stuff(T &stuff_holder) {
  do {
    std::cin.clear();
    std::cin.ignore();
    std::cin >> stuff_holder;
  } while (std::cin.fail());
}

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

int send_credentials(int client_sock, unsigned char *client_tx,
                     std::string &pswd_tmp) {

  std::string username;
  std::string password;

  std::cout << "enter username:" << std::endl;
  std::cin >> username;
  std::cout << "enter password:" << std::endl;
  std::cin >> password;

  // encrypt the username and password and send it over to the server and wait
  // for a resposne

  unsigned char username_ciphertext[username.length() + 1 +
                                    crypto_aead_chacha20poly1305_ABYTES];
  unsigned long long username_ciphertext_len;

  unsigned char password_ciphertext[password.length() + 1 +
                                    crypto_aead_chacha20poly1305_ABYTES];

  unsigned long long password_ciphertext_len;

  unsigned char username_nonce[crypto_aead_chacha20poly1305_NPUBBYTES];
  unsigned char password_nonce[crypto_aead_chacha20poly1305_NPUBBYTES];



  if (encrypt_stream_buffer(client_tx, username_nonce,
                            reinterpret_cast<unsigned char *>(username.data()),
                            username.length() + 1, username_ciphertext,
                            &username_ciphertext_len)) {
    std::cerr
        << "couldn't encrypt error in encrypt_and_send_stream_buffer_with_nonce"
        << std::endl;
  }

  if (encrypt_stream_buffer(client_tx, password_nonce,
                            reinterpret_cast<unsigned char *>(password.data()),
                            password.length() + 1, password_ciphertext,
                            &password_ciphertext_len)) {
    std::cerr
        << "couldn't encrypt error in encrypt_and_send_stream_buffer_with_nonce"
        << std::endl;
  }

  int received_username = -1;

  send(client_sock, username_nonce, crypto_aead_chacha20poly1305_NPUBBYTES, 0);

  send(client_sock, password_nonce, crypto_aead_chacha20poly1305_NPUBBYTES, 0);

  send(client_sock, username_ciphertext, username_ciphertext_len,
       0); // username
  recv(client_sock, &received_username, sizeof(received_username), 0);

  int received_password = -1;

  send(client_sock, password_ciphertext, password_ciphertext_len, 0);
  recv(client_sock, &received_password, sizeof(received_password), 0);

  int auth_stat = -1;

  recv(client_sock, &auth_stat, sizeof(auth_stat), 0);

  if (auth_stat == -1) {
    std::cout << "you sir/madam are not authenticated." << std::endl;
    exit(-1);
  }

  pswd_tmp = password;

  // communications with the server are now authenticated to this point

  sodium_memzero(password.data(), password.size());
  sodium_memzero(username.data(), username.size());

  return 0;
}

int Send_Intention(unsigned char *client_tx, int client_sock, int intent) {

  std::array<unsigned char, sizeof(intent)> arr;

  std::array<unsigned char,
             sizeof(intent) + crypto_aead_chacha20poly1305_ABYTES>
      intention_cipher;
  std::memcpy(arr.data(), &intent, sizeof(intent));

  unsigned long long intention_cipher_size;

  unsigned char intention_nonce[crypto_aead_chacha20poly1305_NPUBBYTES];

  if (encrypt_stream_buffer(client_tx, intention_nonce, arr.data(), arr.size(),
                            intention_cipher.data(), &intention_cipher_size)) {
    return -1;
  }

  // send the nonce and array
  send(client_sock, intention_nonce, crypto_aead_chacha20poly1305_NPUBBYTES, 0);

  send(client_sock, intention_cipher.data(), intention_cipher.size(), 0);

  return 0;
}

int WTFS_Handler(Comms_Agent *CA, int client_sock,
                 unsigned char client_tx[crypto_kx_SESSIONKEYBYTES],
                 unsigned char client_rx[crypto_kx_SESSIONKEYBYTES],
                 std::string &pswd_tmp) {
  std::cerr << "made it here in WTFS_Handler\n";

  Sender_Agent s = Sender_Agent(client_tx, client_rx, client_sock, CA);

  unsigned char
      salt[crypto_pwhash_SALTBYTES]; // needs to be stored in the sqlite db.

  unsigned char key[crypto_box_SEEDBYTES];

  randombytes_buf(
      salt,
      sizeof salt); // this salt is for encryption NOT logging in. for logging
                    // in, the salt is stored with the hash on the server. user
                    // supplies password which is combined with salt to create
                    // hash and if it matches they are in

  std::cout << "made salt, creating key" << std::endl;

  if (crypto_pwhash(key, sizeof key, pswd_tmp.data(), pswd_tmp.length(), salt,
                    crypto_pwhash_OPSLIMIT_INTERACTIVE,
                    crypto_pwhash_MEMLIMIT_INTERACTIVE,
                    crypto_pwhash_ALG_DEFAULT) != 0) {
    /* out of memory */
    std::cerr << "out of mem" << std::endl;
  }

  std::cout << "made key!" << std::endl;

  sodium_memzero(pswd_tmp.data(), pswd_tmp.size());

  s.set_key(key);

  std::cout << "set key!" << std::endl;

  std::cout << "enter file name to send to server" << std::endl;

  std::string file_name;

  get_stuff(file_name);

  int enc_stat = s.encrypt_and_send_to_server(file_name);

  if (enc_stat != 0) {
    std::cerr << "error enc_stat was not 0. error in read_and_create"
              << std::endl;
    return -1;
  }

  return 0;
}

int authed_comms(int client_sock,
                 unsigned char client_tx[crypto_kx_SESSIONKEYBYTES],
                 unsigned char client_rx[crypto_kx_SESSIONKEYBYTES],
                 std::string &pswd_tmp) {

  std::cout << "enter your intention (1 == read || 2 == write)" << std::endl;
  int intention = CONFUSION;

  get_stuff(intention);

  // when writing files, we use pswd_tmp to create a hash with a random salt.
  // then we encrypt the data, and send it along with the random salt to store.
  //
  // when reading files, we use pswd_tmp to create a hash with the random salt
  // attached to the encrypted data on the server, and use this derived key to
  // decrypt on the client side.
  //
  // NO KEYS SHOULD EVER BE IN THE HANDS OF THE SERVER

  // can store the bits of the intention as a char array and send it down the
  // wire

  if (intention == CONFUSION) {
    return -1;
  }
  Comms_Agent CA = Comms_Agent(client_tx, client_rx, client_sock);

  if (intention == READ_FROM_FILESYSTEM) {
    // to be implemented
    // Send_Intention(unsigned char *client_tx, int client_sock, int intent)
    // RFFS_Handler(client_sock, client_tx, pswd_tmp);
  } else if (intention == WRITE_TO_FILESYSTEM) {
    Send_Intention(client_tx, client_sock, intention);
    if (WTFS_Handler(&CA, client_sock, client_tx, client_rx, pswd_tmp)) {
      send(client_sock, &ACK_FAIL, sizeof(ACK_SUC), 0);
    };
  }
  return 0;
}

int main() {

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

  int intention = CONFUSION;

  if (send_credentials(client_sock, client_tx, pswd_tmp)) {
    std::cerr << "exiting login_handle" << std::endl;
  } else {

    char stat;

    do {
      authed_comms(client_sock, client_tx, client_rx, pswd_tmp);
      std::cout
          << "would you like to perform another action? yY/<any other key>"
          << std::endl;
      get_stuff(stat);
    } while (stat == 'y' || stat == 'Y');

  }; // this will contain the rest of the follwoing after
  // no signup, this is only done by the admin of the server who can add
  // themselves to the sql db
}
