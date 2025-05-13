#include "encryption_utils.h"

int encrypt_stream_buffer(unsigned char *client_tx, unsigned char nonce[crypto_aead_chacha20poly1305_NPUBBYTES], unsigned char *msg_box,
                          int message_len, unsigned char *ciphertext,
                          unsigned long long *ciphertext_len, int client_sock) {


  randombytes_buf(nonce, crypto_aead_chacha20poly1305_NPUBBYTES);


  std::cerr << "sent the nonce" << std::endl;

  if (crypto_aead_chacha20poly1305_encrypt(ciphertext, ciphertext_len, msg_box,
                                       message_len, NULL, 0, NULL, nonce,
                                       client_tx)) {
    std::cerr << "encryption failed" <<std::endl;

    return 1;

  }

  std::cerr << "this is the ciphertext_len" << ciphertext_len << std::endl;

  std::cerr << "okay so i sent with client_tx which is " << client_tx
            << "and nonce was " << nonce << std::endl;

  return 0;
}

