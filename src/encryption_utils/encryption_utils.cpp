#include "../../include/common/encryption_utils.h"
#include <cstring>
#include <sodium/crypto_kx.h>
#include <sodium/utils.h>

int encrypt_stream_buffer(
    unsigned char client_tx[crypto_kx_SESSIONKEYBYTES],
    unsigned char nonce[crypto_aead_chacha20poly1305_NPUBBYTES],
    unsigned char *msg_box, unsigned long long message_len, unsigned char *ciphertext,
    unsigned long long *ciphertext_len) {

  randombytes_buf(nonce, crypto_aead_chacha20poly1305_NPUBBYTES);

  if (crypto_aead_chacha20poly1305_encrypt(ciphertext, ciphertext_len, msg_box,
                                           message_len, NULL, 0, NULL, nonce,
                                           client_tx)) {
    std::cerr << "encryption failed" << std::endl;

    return 1;
  }

  return 0;
}

int server_crypt_gen(int client_sock, unsigned char *server_pk,
              unsigned char *server_sk, unsigned char *server_rx,
              unsigned char *server_tx) {

  crypto_kx_keypair(server_pk, server_sk);
  std::cerr << "this is server_pk" << std::endl;

  for (int i = 0; i < crypto_kx_PUBLICKEYBYTES; ++i) {
    printf("%c", server_pk[i]);
  }

  std::cout << std::endl;

  send(client_sock, server_pk, crypto_kx_PUBLICKEYBYTES, 0);

  // receive client_pk from client

  unsigned char client_pk[crypto_kx_PUBLICKEYBYTES];

  if (recv(client_sock, client_pk, crypto_kx_PUBLICKEYBYTES, 0) <= 0) {
    return 2;
  };

  if (crypto_kx_server_session_keys(server_rx, server_tx, server_pk, server_sk,
                                    client_pk) != 0) {
    std::cerr << "imposta client pub key" << std::endl;
    /* Suspicious client public key, bail out */
    return 1;
  }

  std::cerr << "DIDNT BAIL WE HAVE VALID KEYSSS YAYYY" << std::endl;

  return 0;
}


int client_crypt_gen(int client_sock, unsigned char *client_pk,
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
