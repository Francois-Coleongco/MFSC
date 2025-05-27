#include "SessionEnc.h"
#include "encryption_utils.h"
#include <cstring>
#include <sodium/crypto_kx.h>
#include <sodium/utils.h>

enum STREAM_GRAB_TYPE {
  NONCE,
  LENGTH,
  DATA,
};

SessionEncWrapper::SessionEncWrapper(
    unsigned char *data, unsigned long long data_length,
    unsigned char client_tx[crypto_kx_SESSIONKEYBYTES])

    : session_encrypted_data(data),
      session_encrypted_data_length(data_length) { // for writers

  encrypt_stream_buffer(client_tx, this->nonce, data, data_length,
                        this->session_encrypted_data,
                        &this->session_encrypted_data_length);
};

SessionEncWrapper::SessionEncWrapper(int client_sock,
                                     STREAM_GRAB_TYPE grab_type) {
  if (grab_type == NONCE) {
    recv(client_sock, this->nonce, crypto_aead_chacha20poly1305_NPUBBYTES, 0);
  } else if (grab_type == LENGTH) {
    recv(client_sock, &this->session_encrypted_data_length,
         sizeof(this->session_encrypted_data_length), 0);
  } else if (grab_type == DATA) {
    recv(client_sock, this->session_encrypted_data,
         this->session_encrypted_data_length, 0);
  }
};

int SessionEncWrapper::unwrap(
    unsigned char rx[crypto_kx_SESSIONKEYBYTES],
    unsigned char nonce[crypto_aead_chacha20poly1305_NPUBBYTES],
    unsigned char *decrypted_data, unsigned long long *decrypted_data_len) {
  // the data returned within here is up to the caller's interpretation. if the
  // underlying data is encrypted aka was file encrypted or something of the
  // sort, it is the caller's responsibility to decrypt that.

  if (crypto_aead_chacha20poly1305_decrypt(decrypted_data, decrypted_data_len,
                                           NULL, this->session_encrypted_data,
                                           this->session_encrypted_data_length,
                                           NULL, 0, nonce, rx) != 0) {
    std::cerr << "error decrypting in unwrap" << std::endl;
    return 1;
  }
  return 0;
};

SessionEncWrapper::~SessionEncWrapper() {
  sodium_memzero(this->session_encrypted_data,
                 this->session_encrypted_data_length);
  this->session_encrypted_data_length = 0;
}

int SessionEncWrapper::send_data(int client_sock) {
  return send(client_sock, this->session_encrypted_data,
              this->session_encrypted_data_length, 0);
}
int SessionEncWrapper::send_nonce(int client_sock) {
  return send(client_sock, this->nonce, crypto_aead_chacha20poly1305_NPUBBYTES,
              0);
}

int SessionEncWrapper::send_data_length(int client_sock) {
  return send(client_sock, &this->session_encrypted_data_length,
              sizeof(this->session_encrypted_data_length), 0);
}
