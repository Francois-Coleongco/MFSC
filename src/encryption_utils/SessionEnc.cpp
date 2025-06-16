#include "../../include/common/SessionEnc.h"
#include "../../include/common/constants.h"
#include "../../include/common/encryption_utils.h"
#include <cstring>
#include <sodium/crypto_kx.h>
#include <sodium/utils.h>

SessionEncWrapper::SessionEncWrapper(
    const unsigned char *data, unsigned long long data_length,
    unsigned char client_tx[crypto_kx_SESSIONKEYBYTES],
    unsigned char nonce[crypto_aead_chacha20poly1305_NPUBBYTES])
    : session_encrypted_data_length(0) { // for writers

  if (data == nullptr || client_tx == nullptr) {
    return;
  }

  // IMPORTANT the nonce used by encrypt_stream_buffer is the one that gets incremented. this should be accessible past the lifetime of this SessionEncWrapper
  if (encrypt_stream_buffer(client_tx, nonce, data, data_length,
                            this->session_encrypted_data,
                            &this->session_encrypted_data_length)) {
    std::cerr << "encryption inside SessionEncWrapper <for writers> "
                 "construction failed\n";
    return;
  };

  std::memcpy(this->nonce, nonce, crypto_aead_chacha20poly1305_NPUBBYTES);

  this->corrupted = false;
};

SessionEncWrapper::SessionEncWrapper(int client_sock) { // for readers
  if (recv(client_sock, &this->session_encrypted_data_length,
           sizeof(this->session_encrypted_data_length), 0) <= 0) {
    std::cerr << "error in 1 was caused by datalength of: "
              << session_encrypted_data_length << "\n";
  };

  if (session_encrypted_data_length > stream_chunk_size) {
    std::cerr << "error in 2\n";
    return;
  }

  if (recv(client_sock, this->nonce, crypto_aead_chacha20poly1305_NPUBBYTES,
           0) <= 0) {
    std::cerr << "error in 3\n";
    return;
  };
  if (recv(client_sock, this->session_encrypted_data,
           this->session_encrypted_data_length, 0) <= 0) {
    std::cerr << "error in 4\n";
    return;
  };

  this->corrupted = false;
};

int SessionEncWrapper::unwrap(unsigned char rx[crypto_kx_SESSIONKEYBYTES],
                              unsigned long long decrypted_data_capacity,
                              unsigned char *decrypted_data,
                              unsigned long long *decrypted_data_len) {
  // the data returned within here is up to the caller's interpretation. if the
  // underlying data is encrypted aka was file encrypted or something of the
  // sort, it is the caller's responsibility to decrypt that.

  if (this->corrupted) {
    std::cerr << "this wrapper already contains corrupted data\n";
    return 4;
  }

  if (this->session_encrypted_data_length -
          crypto_aead_chacha20poly1305_ABYTES >
      stream_chunk_size) {
    std::cerr << "invalid size, it is larger than stream_chunk_size\n";
    return 3;
  }

  if (this->session_encrypted_data_length -
          crypto_aead_chacha20poly1305_ABYTES >
      decrypted_data_capacity) {
    std::cerr << "WARNING COULD OVERFLOW | TRYING TO PUT "
              << this->session_encrypted_data_length << " BYTES INTO "
              << decrypted_data_capacity << "\n";
    this->corrupted = true;
    return 2;
  }

  std::cerr << this->session_encrypted_data_length << std::endl;

  if (crypto_aead_chacha20poly1305_decrypt(decrypted_data, decrypted_data_len,
                                           NULL, this->session_encrypted_data,
                                           this->session_encrypted_data_length,
                                           NULL, 0, this->nonce, rx) != 0) {
    std::cerr << "error decrypting in unwrap" << std::endl;
    this->corrupted = true;
    return 1;
  }
  return 0;
};

SessionEncWrapper::~SessionEncWrapper() {
  // maybe just zero everything regardless of whether it's corrupt or not
  this->session_encrypted_data_length = 0;
  sodium_memzero(this->session_encrypted_data,
                 this->session_encrypted_data_length);
  sodium_memzero(this->nonce, crypto_aead_chacha20poly1305_NPUBBYTES);
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

unsigned long long SessionEncWrapper::get_data_length() {
  return this->session_encrypted_data_length;
};

bool SessionEncWrapper::is_corrupted() { return this->corrupted; }
