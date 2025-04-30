// everything in this file contains resources for the server after a user is
// authenticated.
#include <cstring>
#include <fstream>
#include <iostream>
#include <sodium/crypto_box.h>
#include <sodium/crypto_pwhash.h>
#include <sys/socket.h>

// need header guardss

const int chunk_size = 4096;

class Sender_Agent {

  int client_sock;
  char *buffer; // buffer capacity is always 4096
  size_t
      size; // the size here refers to the amount of the buffer that is filled
  unsigned char key[crypto_box_SEEDBYTES];
  unsigned char salt[crypto_pwhash_SALTBYTES];

private:
  int send_buffer();
  int send_size();

public:
  // add functionality for directories later
  int fill_and_send(std::string &file_name);

  void set_key(unsigned char new_key[crypto_box_SEEDBYTES]);
  void set_salt(unsigned char new_salt[crypto_pwhash_SALTBYTES]);
  // int encrypt_buffer(char *plain_buf);

  Sender_Agent(int client_sock);

  ~Sender_Agent();
  // copy constructor is kinda weird for here, same as move, i dont think we
  // will need multiple Sender_Agents for the same user
};

class Receiver {

  int client_sock;
  char *buffer; // buffer capacity is always 4096
  size_t
      size; // the size here refers to the amount of the buffer that is filled
};
