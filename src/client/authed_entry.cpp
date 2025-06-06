// everything in this file contains resources for the server after a user is
// authenticated.
#include "../../include/authed_entry.h"
#include "../../include/common/SessionEnc.h"
#include <cstring>
#include <fstream>
#include <iostream>
#include <sodium/crypto_aead_chacha20poly1305.h> // for session encryption
#include <sodium/crypto_box.h>
#include <sodium/crypto_pwhash.h>
#include <sodium/crypto_secretstream_xchacha20poly1305.h> // for file encryption
#include <sodium/utils.h>
#include <sys/socket.h>

Comms_Agent::Comms_Agent(
    unsigned char client_tx[crypto_kx_SESSIONKEYBYTES],
    unsigned char client_rx[crypto_kx_SESSIONKEYBYTES],
    unsigned char original_nonce[crypto_aead_chacha20poly1305_NPUBBYTES],
    int client_sock)
    : client_sock(client_sock) {

  std::memcpy(this->client_tx, client_tx, crypto_kx_SESSIONKEYBYTES);
  std::memcpy(this->client_rx, client_rx, crypto_kx_SESSIONKEYBYTES);

  sodium_memzero(client_tx, crypto_kx_SESSIONKEYBYTES);
  sodium_memzero(client_rx, crypto_kx_SESSIONKEYBYTES);
}

Comms_Agent::~Comms_Agent() {
  this->client_sock = -420;
  sodium_memzero(this->client_rx, crypto_kx_SESSIONKEYBYTES);
  sodium_memzero(this->client_tx, crypto_kx_SESSIONKEYBYTES);
  sodium_memzero(this->original_nonce, crypto_aead_chacha20poly1305_NPUBBYTES);
}

int Comms_Agent::get_socket() { return this->client_sock; }

unsigned char *Comms_Agent::get_client_tx() { return this->client_tx; }

unsigned char *Comms_Agent::get_client_rx() { return this->client_rx; }

unsigned char *Comms_Agent::get_nonce() { return this->original_nonce; }

int Comms_Agent::notify_server_of_action(int action) {
  SessionEncWrapper notif = SessionEncWrapper(
      reinterpret_cast<const unsigned char *>(&action), sizeof(action),
      this->get_client_tx(), this->original_nonce);

  std::cerr << "data length of notif is: " << notif.get_data_length();
  notif.send_data_length(this->client_sock);
  notif.send_nonce(this->client_sock);
  notif.send_data(this->client_sock);

  return 0;
}

int Sender_Agent::send_buffer() {
  // just sends the buffer
  SessionEncWrapper buf_wrap =
      SessionEncWrapper(this->buffer, this->size, this->CA->get_client_tx(),
                        this->CA->get_nonce());
  int client_sock = this->CA->get_socket();
  buf_wrap.send_data_length(client_sock); // swapping these
  buf_wrap.send_nonce(
      client_sock); // around because i need to return if data lenght is 0
  buf_wrap.send_data(client_sock);
  std::cerr << "this is the data length sent via send_buffer "
            << buf_wrap.get_data_length() << "\n";

  return 0;
}

int Sender_Agent::init_send(
    unsigned char file_name[255], unsigned long long file_name_length,
    unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES],
    unsigned char salt[crypto_pwhash_SALTBYTES]) {

  int client_sock = this->CA->get_socket();
  unsigned char *client_tx = this->CA->get_client_tx();

  std::cerr << "sending file_name: " << file_name << " down the wire\n";
  SessionEncWrapper file_name_wrap = SessionEncWrapper(
      file_name, file_name_length, client_tx, this->CA->get_nonce());
  file_name_wrap.send_data_length(client_sock);
  file_name_wrap.send_nonce(
      client_sock); // in the future make this access socket itself via
                    // this->CA->get_socket() internally
  file_name_wrap.send_data(client_sock);

  SessionEncWrapper header_wrap = SessionEncWrapper(
      header, crypto_secretstream_xchacha20poly1305_HEADERBYTES, client_tx,
      this->CA->get_nonce());
  header_wrap.send_data_length(client_sock);
  header_wrap.send_nonce(client_sock);
  header_wrap.send_data(client_sock);

  SessionEncWrapper salt_wrap = SessionEncWrapper(
      salt, crypto_pwhash_SALTBYTES, client_tx, this->CA->get_nonce());
  salt_wrap.send_data_length(client_sock);
  salt_wrap.send_nonce(client_sock);
  salt_wrap.send_data(client_sock);

  return 0;
}

void Sender_Agent::send_end_buffer() {
  sodium_memzero(this->buffer,
                 CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES);
  this->size = CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES;
}

int Sender_Agent::encrypt_and_send_to_server(std::string &file_name,
                                             std::string &password) {

  if (set_crypto(password)) { // reset the keys
    std::cerr << "error in set_crypto\n";
  }

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

  int init_stat = init_send(
      reinterpret_cast<unsigned char *>(file_name.data()), file_name.length(),
      header, this->salt); // no need to plus one here as on server side i check
                           // the length properly

  unsigned char file_chunk[CHUNK_SIZE];

  unsigned char tag = 0;

  do {

    std::cout << "encrypting a chunk wee woo" << std::endl;

    file.read(reinterpret_cast<char *>(file_chunk), CHUNK_SIZE);

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

    SessionEncWrapper prefix =
        tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL
            ? SessionEncWrapper(
                  reinterpret_cast<const unsigned char *>(&END_CHUNK),
                  sizeof(END_CHUNK), this->CA->get_client_tx(),
                  this->CA->get_nonce())
            : SessionEncWrapper(
                  reinterpret_cast<const unsigned char *>(&MEAT_CHUNK),
                  sizeof(MEAT_CHUNK), this->CA->get_client_tx(),
                  this->CA->get_nonce());

    prefix.send_data_length(this->CA->get_socket());
    prefix.send_nonce(this->CA->get_socket());
    prefix.send_data(this->CA->get_socket());

    int send_stat = this->send_buffer();

  } while (!file.eof());

  // when done with file, zero it out so next usage of Sender_Agent will use
  // same object
  sodium_memzero(this->key, crypto_box_SEEDBYTES);
  sodium_memzero(this->salt, crypto_pwhash_SALTBYTES);

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

int Sender_Agent::set_crypto(std::string &password) {
  randombytes_buf(
      this->salt,
      crypto_pwhash_SALTBYTES); // this salt is for encryption NOT logging in.
                                // for logging in, the salt is stored with the
                                // hash on the server in the argon format. user
                                // supplies password which is combined with salt
                                // to create hash and if it matches they are in

  std::cout << "made salt, creating key" << std::endl;

  if (crypto_pwhash(this->key, crypto_box_SEEDBYTES, password.data(),
                    password.size(), salt, crypto_pwhash_OPSLIMIT_INTERACTIVE,
                    crypto_pwhash_MEMLIMIT_INTERACTIVE,
                    crypto_pwhash_ALG_DEFAULT) != 0) {
    /* out of memory */
    std::cerr << "out of mem" << std::endl;
    return 1;
  }
  return 0;
}

Sender_Agent::Sender_Agent(Comms_Agent *CA, std::string &password)
    : size{0}, CA(CA) {

  if (set_crypto(password)) {
    std::cerr << "error in set_crypto\n";
  }
};

Sender_Agent::~Sender_Agent() {
  this->size = 0;
  this->CA = nullptr;
  sodium_memzero(this->key, crypto_box_SEEDBYTES);
  sodium_memzero(this->salt, crypto_pwhash_SALTBYTES);
}

int Receiver_Agent::init_read(
    unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES],
    unsigned char salt[crypto_pwhash_SALTBYTES]) {

  SessionEncWrapper header_wrap = SessionEncWrapper(this->CA->get_socket());
  unsigned long long decrypted_header_len;
  if (header_wrap.unwrap(this->CA->get_client_rx(),
                         crypto_secretstream_xchacha20poly1305_HEADERBYTES,
                         header, &decrypted_header_len)) {
    std::cerr << "couldn't unwrap header\n";
    return 2;
  };

  SessionEncWrapper salt_wrap = SessionEncWrapper(this->CA->get_socket());
  unsigned long long decrypted_salt_len;
  if (salt_wrap.unwrap(this->CA->get_client_rx(), crypto_pwhash_SALTBYTES, salt,
                       &decrypted_salt_len)) {
    std::cerr << "couldn't unwrap header\n";
    return 1;
  }

  return 0;
}

int Receiver_Agent::decrypt_and_read_from_server(std::ofstream &file,
                                                 std::string &password) {
  unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
  unsigned char salt[crypto_pwhash_SALTBYTES];

  if (init_read(header, salt)) {
    std::cerr << "error in init_read\n";
    return 1;
  };

  if (crypto_pwhash(this->key, crypto_box_SEEDBYTES, password.data(),
                    password.length(), salt, crypto_pwhash_OPSLIMIT_INTERACTIVE,
                    crypto_pwhash_MEMLIMIT_INTERACTIVE,
                    crypto_pwhash_ALG_DEFAULT) != 0) {
    /* out of memory */
    std::cerr << "out of mem" << std::endl;
    return 1;
  }

  crypto_secretstream_xchacha20poly1305_state state;

  if (crypto_secretstream_xchacha20poly1305_init_pull(&state, header,
                                                      this->key) != 0) {
    std::cerr << "invalid header\n";
    return 2;
  }

  unsigned char tag = 0;

  int prefix = END_CHUNK;

  do {
    unsigned char *rx = this->CA->get_client_rx();

    unsigned char file_chunk[FILE_ENCRYPTED_CHUNK_SIZE];

    unsigned long long decrypted_prefix_len;

    SessionEncWrapper prefix_wrap = SessionEncWrapper(this->CA->get_socket());

    prefix_wrap.unwrap(rx, sizeof(prefix),
                       reinterpret_cast<unsigned char *>(&prefix),
                       &decrypted_prefix_len);

    SessionEncWrapper file_chunk_wrap =
        SessionEncWrapper(this->CA->get_socket());

    unsigned long long decrypted_file_chunk_len;

    if (file_chunk_wrap.unwrap(this->CA->get_client_rx(),
                               FILE_ENCRYPTED_CHUNK_SIZE, file_chunk,
                               &decrypted_file_chunk_len)) {
      std::cerr << "error decrypting file_chunk_wrap in pulling loop\n";
      return 1;
    }

    unsigned char decrypted_file_chunk
        [FILE_ENCRYPTED_CHUNK_SIZE]; // just to be safe, keep buffer size the
                                     // same, not smaller, we can just use
                                     // decrypted_len from the pull function
                                     // below to tell how many bytes to write to
                                     // the end file

    if (crypto_secretstream_xchacha20poly1305_pull(
            &state, file_chunk, NULL, &tag, decrypted_file_chunk,
            FILE_ENCRYPTED_CHUNK_SIZE, NULL, 0) != 0) {
      std::cerr << "decryption failed in "
                   "crypto_secretstream_xchacha20poly1305_pull\n";
      return 2;
    }

  } while (prefix != END_CHUNK);

  return 0;
}

Receiver_Agent::Receiver_Agent(Comms_Agent *CA) : size(0), CA(CA) {}
Receiver_Agent::~Receiver_Agent() {
  this->size = 0;
  this->CA = nullptr;
  sodium_memzero(this->key, crypto_box_SEEDBYTES);
}
