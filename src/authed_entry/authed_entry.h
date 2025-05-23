// everything in this file contains resources for the server after a user is
// authenticated.
#include <cstring>
#include <fstream>
#include <iostream>
#include <sodium/crypto_box.h>
#include <sodium/crypto_pwhash.h>
#include <sys/socket.h>
#include <sodium/crypto_kx.h>

// need header guardss

const size_t chunk_size = 4096;

class Sender_Agent {

  int client_sock;
  unsigned char client_tx[crypto_kx_SESSIONKEYBYTES];
  unsigned char *buffer; // buffer capacity is always 4096
  size_t
      size; // the size here refers to the amount of the buffer that is filled
  unsigned char key[crypto_box_SEEDBYTES];
  unsigned char salt[crypto_pwhash_SALTBYTES];

private:
  int send_buffer();

public:
  // add functionality for directories later
  int encrypt_and_send_to_server(std::string &file_name);
  int fill_and_send(std::string &file_name);

  void set_key(unsigned char new_key[crypto_box_SEEDBYTES]);
  void set_salt(unsigned char new_salt[crypto_pwhash_SALTBYTES]);

  Sender_Agent(unsigned char client_tx[crypto_kx_SESSIONKEYBYTES], int client_sock);

  ~Sender_Agent();
  // copy constructor is kinda weird for here, same as move, i dont think we
  // will need multiple Sender_Agents for the same user
};

class Receiver {
  // should inherit similar things to Sender from a base class i have not created yet

  int client_sock;
  char *buffer; // buffer capacity is always 4096
  size_t
      size; // the size here refers to the amount of the buffer that is filled
};
