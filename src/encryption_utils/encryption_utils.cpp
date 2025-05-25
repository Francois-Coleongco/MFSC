#include "encryption_utils.h"
#include <sodium/crypto_kx.h>

int encrypt_stream_buffer(unsigned char client_tx[crypto_kx_SESSIONKEYBYTES], unsigned char nonce[crypto_aead_chacha20poly1305_NPUBBYTES], unsigned char *msg_box,
                          int message_len, unsigned char *ciphertext,
                          unsigned long long *ciphertext_len) {


  randombytes_buf(nonce, crypto_aead_chacha20poly1305_NPUBBYTES);


  if (crypto_aead_chacha20poly1305_encrypt(ciphertext, ciphertext_len, msg_box,
                                       message_len, NULL, 0, NULL, nonce,
                                       client_tx)) {
    std::cerr << "encryption failed" <<std::endl;

    return 1;

  }

  return 0;
}

