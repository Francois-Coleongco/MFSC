// everything in this file contains resources for the server after a user is
// authenticated.
#include "authed_entry.h"
#include <cstring>
#include <fstream>
#include <iostream>
#include <sodium/crypto_box.h>
#include <sodium/crypto_pwhash.h>
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

int Sender_Agent::fill_and_send(
    std::string &file_name) { // this takes in a file containing
                              // already encrypted data.

  std::ifstream file(file_name, std::ios::binary);
  // the file that is passed must be an already encrypted file done by another
  // func;

  if (!file) {
    std::cerr << "couldn't open the file" << std::endl;
    return -1;
  }

  while (file) {
    file.read(this->buffer, chunk_size);
    this->size = file.gcount();
    this->send_size(); // always send size of buffer before the actual buffer
    this->send_buffer();
  }

  // start by sending the size, then send the encrypted bytes
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
    : client_sock{client_sock}, buffer(new char[4096]), size{0}, key{} {};

Sender_Agent::~Sender_Agent() {
  delete[] this->buffer;
}
// copy constructor is kinda weird for here, same as move, i dont think we
// will need multiple Sender_Agents for the same user

;
