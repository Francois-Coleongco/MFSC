#include "../../include/common/SessionEnc.h"
#include "../../include/common/encryption_utils.h"
#include <cstring>
#include <sodium/crypto_kx.h>
#include <sodium/utils.h>

SessionEncWrapper::SessionEncWrapper(
    unsigned char *data, unsigned long long data_length,
    unsigned char client_tx[crypto_kx_SESSIONKEYBYTES]) { // for writers

  encrypt_stream_buffer(client_tx, this->nonce, data, data_length,
                        this->session_encrypted_data,
                        &this->session_encrypted_data_length);
};

SessionEncWrapper::SessionEncWrapper(int client_sock) { // for readers
  std::cerr << "started reading construction\n";
  if (recv(client_sock, &this->session_encrypted_data_length,
           sizeof(this->session_encrypted_data_length), 0) <= 0) {
    this->corrupted = true;
    return;
  };

  if (session_encrypted_data_length == 0 ||
      session_encrypted_data_length > stream_chunk_size) {
    this->corrupted = true;
    return;
  }
  if (recv(client_sock, this->nonce, crypto_aead_chacha20poly1305_NPUBBYTES,
           0) <= 0) {
    this->corrupted = true;
    return;
  };
  if (recv(client_sock, this->session_encrypted_data,
           this->session_encrypted_data_length, 0) <= 0) {
    this->corrupted = true;
    return;
  };

  this->corrupted = false;
  std::cerr << "finished reading construction\n";
};

int SessionEncWrapper::unwrap(unsigned char rx[crypto_kx_SESSIONKEYBYTES],
                              unsigned long long decrypted_data_capacity,
                              unsigned char *decrypted_data,
                              unsigned long long *decrypted_data_len) {
  // the data returned within here is up to the caller's interpretation. if the
  // underlying data is encrypted aka was file encrypted or something of the
  // sort, it is the caller's responsibility to decrypt that.
  if (this->session_encrypted_data_length -
          crypto_secretstream_xchacha20poly1305_ABYTES >
      decrypted_data_capacity) {

    std::cerr << "WARNING COULD OVERFLOW | TRYING TO PUT "
              << this->session_encrypted_data_length << " BYTES INTO"
              << decrypted_data_capacity << "\n";
    this->corrupted = true;
    return 2;
  }

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
  if (this->corrupted) {
    return;
  }
  sodium_memzero(this->session_encrypted_data,
                 this->session_encrypted_data_length);
  this->session_encrypted_data_length = 0;
}

int SessionEncWrapper::send_data(int client_sock) {
  return send(client_sock, this->session_encrypted_data,
              this->session_encrypted_data_length, 0);
}
int SessionEncWrapper::send_nonce(int client_sock) {
  std::cerr << "\n\n";
  std::cerr << "nonce sent was: " << this->nonce << "\n\n";
  return send(client_sock, this->nonce, crypto_aead_chacha20poly1305_NPUBBYTES,
              0);
}

int SessionEncWrapper::send_data_length(int client_sock) {
  std::cerr << "datalength sent " << this->session_encrypted_data_length
            << "\n";
  return send(client_sock, &this->session_encrypted_data_length,
              sizeof(this->session_encrypted_data_length), 0);
}

unsigned char *SessionEncWrapper::get_nonce() { return this->nonce; }

unsigned long long SessionEncWrapper::get_data_length() {
  return this->session_encrypted_data_length;
};

int SessionEncWrapper::write_to_file(std::ofstream &file) {
  file.write(reinterpret_cast<const char *>(this->session_encrypted_data),
             this->session_encrypted_data_length);

  if (!file) {
    return 1;
  }

  return 0;
};

bool SessionEncWrapper::is_corrupted() { return this->corrupted; }
