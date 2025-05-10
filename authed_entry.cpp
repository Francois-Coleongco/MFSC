// everything in this file contains resources for the server after a user is
// authenticated.
#include "authed_entry.h"
#include <cstring>
#include <fstream>
#include <iostream>
#include <sodium/crypto_box.h>
#include <sodium/crypto_pwhash.h>
#include <sodium/crypto_secretstream_xchacha20poly1305.h>
#include <sys/socket.h>

int Sender_Agent::send_size() {
  int sent_bytes =
      send(this->client_sock, &(this->size), sizeof(this->size), 0);
  // just sends the size
  return sent_bytes;
}

int Sender_Agent::send_buffer() {
  // just sends the buffer
  int sent_bytes = send(this->client_sock, buffer, this->size, 0);
  return sent_bytes;
}

// int encrypt_buffer(char *plain_buf) { this->key }
// add functionality for directories later
int Sender_Agent::read_and_send(std::string &file_name) {

  std::ifstream file(file_name, std::ios::binary);
  // the file that is passed must be an already encrypted file done by another
  // func;

  if (!file) {
    std::cerr << "couldn't open the file" << std::endl;
    return -1;
  }

  crypto_secretstream_xchacha20poly1305_state state;

  unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES];
  unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
  crypto_secretstream_xchacha20poly1305_init_push(&state, header, this->key);


  do {

    unsigned char message_buffer[chunk_size];
    file.read(reinterpret_cast<char *>(message_buffer), chunk_size);

    crypto_secretstream_xchacha20poly1305_state state;

    unsigned long long message_buffer_len = file.gcount();

    unsigned long long ciphertext_len = crypto_secretstream_xchacha20poly1305_ABYTES + message_buffer_len;

    this->size = ciphertext_len;

    int tag = file.eof() ? crypto_secretstream_xchacha20poly1305_TAG_FINAL : 0;

    crypto_secretstream_xchacha20poly1305_push(&state, this->buffer, &ciphertext_len, message_buffer, message_buffer_len, NULL, 0, tag); // encrypt it straight into the buffer

    this->send_size();
    this->send_buffer();

  } while (!file.eof());

  return 0;
}

void Sender_Agent::set_key(unsigned char new_key[crypto_box_SEEDBYTES]) {
  std::memcpy(this->key, new_key, crypto_box_SEEDBYTES);
  std::memset(new_key, 0, crypto_box_SEEDBYTES);
}

void Sender_Agent::set_salt(unsigned char new_salt[crypto_pwhash_SALTBYTES]) {
  std::memcpy(this->salt, new_salt, crypto_pwhash_SALTBYTES);
  std::memset(new_salt, 0, crypto_pwhash_SALTBYTES);
}

Sender_Agent::Sender_Agent(int client_sock)
    : client_sock{client_sock}, buffer(new unsigned char[chunk_size + crypto_secretstream_xchacha20poly1305_ABYTES]), size{0}, key{} {}; // remember the buffer here holds the ciphertext not the message

Sender_Agent::~Sender_Agent() {
  delete[] this->buffer;
  this->size = 0;
  memset(this->key, 0, 32);
}
// copy constructor is kinda weird for here, same as move, i dont think we
// will need multiple Sender_Agents for the same user

;
