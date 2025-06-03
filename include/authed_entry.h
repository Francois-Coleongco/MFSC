// everything in this file contains resources for the server after a user is
// authenticated.
#include <cstring>
#include <fstream>
#include <iostream>
#include <sodium/crypto_box.h>
#include <sodium/crypto_kx.h>
#include <sodium/crypto_pwhash.h>
#include <sodium/crypto_secretstream_xchacha20poly1305.h>
#include <sys/socket.h>

// need header guardss

class Comms_Agent {
  int client_sock;
  bool SA_active;
  bool RA_active;
  unsigned char client_tx[crypto_kx_SESSIONKEYBYTES];
  unsigned char client_rx[crypto_kx_SESSIONKEYBYTES];

public:
  int get_socket();

  int notify_server_of_new_action();
  void set_SA_status(bool stat);
  void set_RA_status(bool stat);
  bool SA_stat();
  bool RA_stat();

  unsigned char *get_client_tx();
  unsigned char *get_client_rx();

  // these will be
  int set_client_tx(unsigned char client_tx[crypto_kx_SESSIONKEYBYTES]);
  int set_client_rx(unsigned char client_rx[crypto_kx_SESSIONKEYBYTES]);
  // used to rotate the keys

  Comms_Agent(unsigned char client_tx[crypto_kx_SESSIONKEYBYTES],
              unsigned char client_rx[crypto_kx_SESSIONKEYBYTES],
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
  int init_send(
      unsigned char file_name[255], unsigned long long file_name_length,
      unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES],
      unsigned char salt[crypto_pwhash_SALTBYTES]);

public:
  // add functionality for directories later
  int encrypt_and_send_to_server(std::string &file_name);
  int fill_and_send(std::string &file_name);

  void set_key(unsigned char new_key[crypto_box_SEEDBYTES]);
  void set_salt(unsigned char new_salt[crypto_pwhash_SALTBYTES]);
  int set_crypto(std::string &password);

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
  unsigned char salt[crypto_pwhash_SALTBYTES];
  Comms_Agent *CA;

public:
  int decrypt_and_read_from_server(std::string &file_name);
  // Receiver_Agent(Comms_Agent *CA, );
  ~Receiver_Agent();
};
