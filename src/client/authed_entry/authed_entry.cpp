// everything in this file contains resources for the server after a user is
// authenticated.
#include "authed_entry.h"
#include "../../encryption_utils/encryption_utils.h"
#include <cstring>
#include <fstream>
#include <iostream>
#include <sodium/crypto_aead_chacha20poly1305.h> // for session encryption
#include <sodium/crypto_box.h>
#include <sodium/crypto_pwhash.h>
#include <sodium/crypto_secretstream_xchacha20poly1305.h> // for file encryption
#include <sodium/utils.h>
#include <sys/socket.h>

Comms_Agent::Comms_Agent(unsigned char client_tx[crypto_kx_SESSIONKEYBYTES],
                         unsigned char client_rx[crypto_kx_SESSIONKEYBYTES],
                         int client_sock)
    : client_sock(client_sock) {
  std::memcpy(this->client_tx, client_tx, crypto_kx_SESSIONKEYBYTES);
  std::memcpy(this->client_rx, client_rx, crypto_kx_SESSIONKEYBYTES);
}

Comms_Agent::~Comms_Agent() {
  this->client_sock = -420;
  sodium_memzero(this->client_rx, crypto_kx_SESSIONKEYBYTES);
  sodium_memzero(this->client_tx, crypto_kx_SESSIONKEYBYTES);
}

int Comms_Agent::get_socket() { return this->client_sock; }

unsigned char *Comms_Agent::get_client_tx() { return this->client_tx; }

unsigned char *Comms_Agent::get_client_rx() { return this->client_rx; }

int Sender_Agent::send_buffer() {
  // just sends the buffer

  unsigned char nonce[crypto_aead_chacha20poly1305_NPUBBYTES];
  unsigned char ciphertext[this->size + crypto_aead_chacha20poly1305_ABYTES];
  unsigned long long ciphertext_len;

  encrypt_stream_buffer(this->CA->get_client_tx(), nonce, this->buffer,
                        this->size, ciphertext, &ciphertext_len);
  int bytes_to_send_stat =
      send(this->CA->get_socket(), &this->size, sizeof(this->size),
           0); // need to send this using the encrypt_stream_buffer func as well
  // int buffer_bytes_stat =
  //     send(this->CA->get_socket(), ciphertext, ciphertext_len, 0);
  std::cerr << "sock " << this->CA->get_socket() << "\n";

  return 0;
}

// int encrypt_buffer(char *plain_buf) { this->key }
// add functionality for directories later

int Sender_Agent::init_send(
    unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES],
    unsigned char salt[crypto_pwhash_SALTBYTES]) {

  std::cerr << "started init_send\n";
  int header_send_stat =
      send(this->CA->get_socket(), header,
           crypto_secretstream_xchacha20poly1305_HEADERBYTES, 0);
  int salt_send_stat =
      send(this->CA->get_socket(), salt, crypto_pwhash_SALTBYTES, 0);

  std::cerr << header_send_stat << "\n";
  std::cerr << salt_send_stat << "\n";
  return 0;
}

int Sender_Agent::encrypt_and_send_to_server(std::string &file_name) {

  std::ifstream file(file_name, std::ios::binary);
  // the file that is passed must be an already encrypted file done by another
  // func;

  if (!file) {
    std::cerr << "couldn't open the file" << std::endl;
    return -1;
  }

  std::cerr << "starting encrypt_and_send_to_server\n";
  std::cerr << "test: \n" << this->CA->get_socket() << "\n";

  crypto_secretstream_xchacha20poly1305_state state;

  // this->salt; // 16 bytes
  unsigned char
      header[crypto_secretstream_xchacha20poly1305_HEADERBYTES]; // 24 bytes

  crypto_secretstream_xchacha20poly1305_init_push(&state, header, this->key);

  std::cerr << "this->key " << this->key << "\n";

  int init_stat = init_send(header, this->salt);

  std::cerr << "past init_send\n";

  unsigned char message_buffer[chunk_size];

  int tag = 0;

  do {

    std::cout << "encrypting a chunk wee woo" << std::endl;

    file.read(reinterpret_cast<char *>(message_buffer), chunk_size);

    unsigned long long message_buffer_len = file.gcount();

    std::cerr << "read message_buffer_len " << message_buffer_len << "\n";

    unsigned long long ciphertext_len =
        crypto_secretstream_xchacha20poly1305_ABYTES + message_buffer_len;

    this->size = ciphertext_len;

    tag = file.eof() ? crypto_secretstream_xchacha20poly1305_TAG_FINAL : 0;

    std::cerr << "tag is " << tag << "\n";

    crypto_secretstream_xchacha20poly1305_push(
        &state, this->buffer, &ciphertext_len, message_buffer,
        message_buffer_len, NULL, 0,
        tag); // encrypt it straight into the buffer

    // send_size and send_buffer should be modified to use the session
    // encryption

    // int send_stat = this->send_buffer(); //this func needs major fixing
    //
  } while (!file.eof());

  return 0;
}

void Sender_Agent::set_key(unsigned char new_key[crypto_box_SEEDBYTES]) {
  std::memcpy(this->key, new_key, crypto_box_SEEDBYTES);
  sodium_memzero(new_key, crypto_box_SEEDBYTES);
}

void Sender_Agent::set_salt(unsigned char new_salt[crypto_pwhash_SALTBYTES]) {
  std::memcpy(this->salt, new_salt, crypto_pwhash_SALTBYTES);
  sodium_memzero(new_salt, crypto_pwhash_SALTBYTES);
}

Sender_Agent::Sender_Agent(unsigned char client_tx[crypto_kx_SESSIONKEYBYTES],
                           unsigned char client_rx[crypto_kx_SESSIONKEYBYTES],
                           int client_sock, Comms_Agent *CA)
    : size{0}, CA(CA), key{} {
  std::memcpy(this->CA->get_client_tx(), client_tx, crypto_kx_SESSIONKEYBYTES);
  sodium_memzero(client_tx, crypto_kx_SESSIONKEYBYTES);
}; // remember the buffer here holds the ciphertext not the message

Sender_Agent::~Sender_Agent() {
  this->size = 0;
  sodium_memzero(this->key, crypto_box_SEEDBYTES);
}

;
