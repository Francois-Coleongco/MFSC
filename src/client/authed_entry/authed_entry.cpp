// everything in this file contains resources for the server after a user is
// authenticated.
#include "authed_entry.h"
#include "../../encryption_utils/SessionEnc.h"
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
  SessionEncWrapper buf_wrap =
      SessionEncWrapper(this->buffer, this->size, this->CA->get_client_tx());
  int client_sock = this->CA->get_socket();
  buf_wrap.send_data_length(client_sock); // swapping these
  buf_wrap.send_nonce(
      client_sock); // around because i need to return if data lenght is 0
  buf_wrap.send_data(client_sock);

  return 0;
}

// int encrypt_buffer(char *plain_buf) { this->key }
// add functionality for directories later

int Sender_Agent::init_send(
    unsigned char file_name[255], unsigned long long file_name_length,
    unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES],
    unsigned char salt[crypto_pwhash_SALTBYTES]) {

  std::cerr << "started init_send\n";

  std::cerr << "this is filename before encryption: " << file_name;
  std::cerr << "this is header before encryption: " << header;
  std::cerr << "this is salt before encryption: " << salt;

  int client_sock = this->CA->get_socket();
  unsigned char *client_tx = this->CA->get_client_tx();

  SessionEncWrapper file_name_wrap =
      SessionEncWrapper(file_name, file_name_length, client_tx);
  file_name_wrap.send_data_length(client_sock);
  file_name_wrap.send_nonce(
      client_sock); // in the future make this access socket itself via
                    // this->CA->get_socket() internally
  file_name_wrap.send_data(client_sock);

  SessionEncWrapper header_wrap = SessionEncWrapper(
      header, crypto_secretstream_xchacha20poly1305_HEADERBYTES, client_tx);
  header_wrap.send_data_length(client_sock);
  header_wrap.send_nonce(client_sock);
  header_wrap.send_data(client_sock);

  SessionEncWrapper salt_wrap =
      SessionEncWrapper(salt, crypto_pwhash_SALTBYTES, client_tx);
  salt_wrap.send_data_length(client_sock);
  salt_wrap.send_nonce(client_sock);
  salt_wrap.send_data(client_sock);

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

  crypto_secretstream_xchacha20poly1305_init_push(
      &state, header,
      this->key); //  the salt used to create this key needs to be saved with
                  //  the encrypted file. this is to be combined with the user's
                  //  password to recreate this exact key which is what's needed
                  //  for decryption

  std::cerr << "this->key " << this->key << "\n";

  std::cerr << "this is header before INIT SEND " << header << "\n";
  std::cerr << "this is salt before INIT SEND " << this->salt << "\n";

  int init_stat = init_send(reinterpret_cast<unsigned char *>(file_name.data()),
                            file_name.length(), header, this->salt);

  std::cerr << "debug end client\n";

  unsigned char file_chunk[chunk_size];

  int tag = 0;

  do {

    std::cout << "encrypting a chunk wee woo" << std::endl;

    file.read(reinterpret_cast<char *>(file_chunk), chunk_size);

    unsigned long long file_chunk_len = file.gcount();

    std::cerr << "read file_chunk_len " << file_chunk_len << "\n";

    unsigned long long ciphertext_len =
        crypto_secretstream_xchacha20poly1305_ABYTES + file_chunk_len;

    this->size = ciphertext_len;

    tag = file.eof() ? crypto_secretstream_xchacha20poly1305_TAG_FINAL : 0;

    std::cerr << "tag is " << tag << "\n";

    crypto_secretstream_xchacha20poly1305_push(
        &state, this->buffer, &ciphertext_len, file_chunk, file_chunk_len, NULL,
        0,
        tag); // encrypt it straight into the buffer

    int send_stat = this->send_buffer();

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
