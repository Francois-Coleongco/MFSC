#include "encryption_utils.h"

int encrypt_stream_buffer(unsigned char *client_tx, unsigned char *msg_box,
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

