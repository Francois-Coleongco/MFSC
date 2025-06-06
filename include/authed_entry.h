// everything in this file contains resources for the server after a user is
// authenticated.
#include "./common/constants.h"
#include <cstring>
#include <fstream>
#include <iostream>
#include <sodium/crypto_box.h>
#include <sodium/crypto_kx.h>
#include <sodium/crypto_pwhash.h>
#include <sodium/crypto_secretstream_xchacha20poly1305.h>
#include <sys/socket.h>

#ifndef AUTHED_ENTRY
#define AUTHED_ENTRY

// need header guardss

class Comms_Agent {
  int client_sock;
  size_t SA_count; // these will be used to count the number of active Sender
                   // and Receiver instances
  size_t RA_count; // need these for the future for concurrent reads and writes
                   // as they each are independent to a respective file
  // with that, we will need a thread pool, the pool perhaps being
  // another unordered list keyed by the file names
  // after a certain amount of time being unused in the pool, force the thread
  // to complete so it's SA/RA goes out of scope and destructor is callsed
  unsigned char client_tx[crypto_kx_SESSIONKEYBYTES];
  unsigned char client_rx[crypto_kx_SESSIONKEYBYTES];
  unsigned char original_nonce[crypto_aead_chacha20poly1305_NPUBBYTES];

public:
  int get_socket();

  int notify_server_of_action(int action);

  unsigned char *get_client_tx();
  unsigned char *get_client_rx();
  unsigned char *get_nonce();

  // these will be
  int set_client_tx(unsigned char client_tx[crypto_kx_SESSIONKEYBYTES]);
  int set_client_rx(unsigned char client_rx[crypto_kx_SESSIONKEYBYTES]);
  // used to rotate the keys

  Comms_Agent(
      unsigned char client_tx[crypto_kx_SESSIONKEYBYTES],
      unsigned char client_rx[crypto_kx_SESSIONKEYBYTES],
      unsigned char original_nonce[crypto_aead_chacha20poly1305_NPUBBYTES],
      int client_sock);
  ~Comms_Agent();
};

class Sender_Agent {

  unsigned char
      buffer[CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES];
  unsigned long long
      size; // the size here refers to the amount of the buffer that is filled
  unsigned char key[crypto_box_SEEDBYTES];
  unsigned char salt[crypto_pwhash_SALTBYTES];
  Comms_Agent *CA;

private:
  int send_buffer();
  void send_end_buffer();
  int init_send(
      unsigned char file_name[255], unsigned long long file_name_length,
      unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES],
      unsigned char salt[crypto_pwhash_SALTBYTES]);

  void set_key(unsigned char new_key[crypto_box_SEEDBYTES]);
  void set_salt(unsigned char new_salt[crypto_pwhash_SALTBYTES]);
  int set_crypto(std::string &password);

public:
  // add functionality for directories later
  int encrypt_and_send_to_server(std::string &file_name, std::string &password);
  int fill_and_send(std::string &file_name);

  Sender_Agent(Comms_Agent *CA, std::string &password);

  ~Sender_Agent();
  // copy constructor is kinda weird for here, same as move, i dont think we
  // will need multiple Sender_Agents for the same user
};

class Receiver_Agent {
  unsigned char
      buffer[CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES];
  unsigned long long
      size; // the size here refers to the amount of the buffer that is filled
  unsigned char key[crypto_box_SEEDBYTES];
  Comms_Agent *CA;

public:
  int decrypt_and_read_from_server(
      std::ofstream &file,
      std::string &password); // internally handles set_crypto for itself
  Receiver_Agent(Comms_Agent *CA);

  int init_read(
      unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES],
      unsigned char salt[crypto_pwhash_SALTBYTES]);
  ~Receiver_Agent();
};
#endif
