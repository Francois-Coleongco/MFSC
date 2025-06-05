#include "../../include/read_write_handlers.h"
#include <cstdio>
#include <cstring>
#include <sodium/utils.h>

const std::string ext = ".enc";

FS_Operator::FS_Operator(int client_sock,
                         unsigned char server_rx[crypto_kx_SESSIONKEYBYTES],
                         unsigned char server_tx[crypto_kx_SESSIONKEYBYTES],
                         unsigned char nonce[crypto_kx_SESSIONKEYBYTES])
    : client_sock(client_sock) {

  std::memcpy(this->server_tx, server_tx, crypto_kx_SESSIONKEYBYTES);
  std::memcpy(this->server_rx, server_rx, crypto_kx_SESSIONKEYBYTES);
  std::memcpy(this->nonce, server_rx, crypto_kx_SESSIONKEYBYTES);

  sodium_memzero(server_tx, crypto_kx_SESSIONKEYBYTES);
  sodium_memzero(server_rx, crypto_kx_SESSIONKEYBYTES);
  sodium_memzero(nonce, crypto_kx_SESSIONKEYBYTES);
}

FS_Operator::~FS_Operator() {
  this->client_sock = -420;
  sodium_memzero(this->server_tx, crypto_kx_SESSIONKEYBYTES);
  sodium_memzero(this->server_rx, crypto_kx_SESSIONKEYBYTES);
}

int FS_Operator::init_read(
    int client_sock, char file_name_buf[250],
    unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES],
    unsigned char salt[crypto_pwhash_SALTBYTES]) {

  unsigned long long decrypted_file_name_length;
  SessionEncWrapper file_name_wrap = SessionEncWrapper(client_sock);
  std::cerr << "outside construction now\n";
  if (file_name_wrap.is_corrupted()) {
    std::cerr << "it's corrupted i see from outsideeeeeeee\n";
    return 2;
  }

  if (file_name_wrap.unwrap(this->server_rx, PRE_EXT_FILE_NAME_LEN,
                            reinterpret_cast<unsigned char *>(file_name_buf),
                            &decrypted_file_name_length) == 2) {
    std::cerr << "couldn't read file name, ABORT\n";
    return 1;
  }

  std::cerr << "decrypted_file_name_length: " << decrypted_file_name_length
            << "\n";

  // decrypted file length will be NOT null terminated. so i need to null
  // terminate it before it leaves int_read

  if (decrypted_file_name_length + ext.length() > MAX_FILE_NAME_LENGTH) {
    return 2;
  }

  file_name_buf[decrypted_file_name_length] = '\0';

  unsigned long long decrypted_header_length;
  SessionEncWrapper header_wrap = SessionEncWrapper(client_sock);
  header_wrap.unwrap(this->server_rx,
                     crypto_secretstream_xchacha20poly1305_HEADERBYTES, header,
                     &decrypted_header_length);

  std::cerr << "decrypted header length\n" << decrypted_header_length << "\n";

  SessionEncWrapper salt_wrap = SessionEncWrapper(client_sock);
  unsigned long long decrypted_salt_length;
  salt_wrap.unwrap(this->server_rx, crypto_pwhash_SALTBYTES, salt,
                   &decrypted_salt_length);

  std::cerr << "decrypted salt length\n" << decrypted_salt_length << "\n";

  return 0;
}

int FS_Operator::WTFS_Handler__Server() {

  // when doing multiple files and directories, this function could be called in
  // a separate thread perhaps for each file

  char file_name_buf[FILE_ENCRYPTED_CHUNK_SIZE];

  unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
  unsigned char salt[crypto_pwhash_SALTBYTES];

  if (init_read(this->client_sock, file_name_buf, header, salt)) {
    return 1;
  }

  std::string file_name = file_name_buf;

  file_name.append(".enc");

  std::cerr << "this is file_name now after adding ext: " << file_name << "\n";

  std::ofstream file(file_name, std::ios::binary);

  file.write(reinterpret_cast<const char *>(header),
             crypto_secretstream_xchacha20poly1305_HEADERBYTES);
  file.write(reinterpret_cast<const char *>(salt), crypto_pwhash_SALTBYTES);

  unsigned char read_buf[stream_chunk_size];
  size_t read_bytes;

  int prefix = END_CHUNK;
  do {
    unsigned long long decrypted_prefix_len;
    SessionEncWrapper prefix_wrap = SessionEncWrapper(client_sock);
    SessionEncWrapper encrypted_data_wrap = SessionEncWrapper(client_sock);
    prefix_wrap.unwrap(this->server_rx, sizeof(prefix),
                       reinterpret_cast<unsigned char *>(&prefix),
                       &decrypted_prefix_len);
    if (prefix == END_CHUNK) {
      std::cerr << "found last chunk\n";
      break; // we came across the last chunk already in the previous iteration
    }
    encrypted_data_wrap.write_to_file(file);
  } while (prefix != END_CHUNK);

  return 0;
}

int FS_Operator::RFFS_Handler__Server() {

  char file_name_buf[MAX_FILE_NAME_LENGTH];

  unsigned long long decrypted_file_name_length;

  SessionEncWrapper encrypted_file_name = SessionEncWrapper(client_sock);

  encrypted_file_name.unwrap(this->server_rx, PRE_EXT_FILE_NAME_LEN,
                             reinterpret_cast<unsigned char *>(file_name_buf),
                             &decrypted_file_name_length);

  std::ifstream file(file_name_buf, std::ios::binary);

  if (!file) {
    std::cerr << "couldn't open the file" << std::endl;
    return -1;
  }

  unsigned char file_chunk[CHUNK_SIZE];

  int tag = 0;

  do {

    file.read(reinterpret_cast<char *>(file_chunk), CHUNK_SIZE);

    unsigned long long file_chunk_len = file.gcount();

    std::cerr << "read file_chunk_len " << file_chunk_len << "\n";

    send(this->client_sock, file_chunk, file_chunk_len, 0);
  } while (!file.eof());
  return 0;
}

int FS_Operator::receive_notice_of_new_action() {
  int notice;
  SessionEncWrapper notice_wrap = SessionEncWrapper(this->client_sock);
  unsigned long long decrypted_notice_length;
  notice_wrap.unwrap(this->server_rx, sizeof(notice),
                     reinterpret_cast<unsigned char *>(&notice),
                     &decrypted_notice_length);

  if (notice != NEW_ACTION) {
    std::cerr << "RETURNED ONE FROM NEWACTION NOOOOOOOOOOOOOO\n";
    return 1;
  } else {
    std::cerr << "NEW ACTION INISIATED\n";
    return 0;
  }
}

int FS_Operator::read_intent() {

  int intent;

  unsigned long long decrypted_data_length;

  SessionEncWrapper nonce_wrap = SessionEncWrapper(client_sock);

  nonce_wrap.unwrap(server_rx, sizeof(intent),
                    reinterpret_cast<unsigned char *>(&intent),
                    &decrypted_data_length);

  std::cerr << "this was the intent read: " << intent << "\n";
  return intent;
}
