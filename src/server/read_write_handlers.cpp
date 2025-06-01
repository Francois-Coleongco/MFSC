#include "../../include/read_write_handlers.h"
#include <cstring>
#include <sodium/utils.h>

const unsigned char FILE_NAME_BUF_SIZE =
    250; // remove 5 from 255 because that is reserved for the .enc extension
         // (null byte included)
const std::string ext = ".enc";
const unsigned long long CHUNK_SIZE = 4096;

FS_Operator::FS_Operator(int client_sock,
                         unsigned char server_rx[crypto_kx_SESSIONKEYBYTES],
                         unsigned char server_tx[crypto_kx_SESSIONKEYBYTES])
    : client_sock(client_sock) {

  std::memcpy(this->server_tx, server_tx, crypto_kx_SESSIONKEYBYTES);
  std::memcpy(this->server_rx, server_rx, crypto_kx_SESSIONKEYBYTES);

  sodium_memzero(server_tx, crypto_kx_SESSIONKEYBYTES);
  sodium_memzero(server_rx, crypto_kx_SESSIONKEYBYTES);
}

FS_Operator::~FS_Operator() {
  this->client_sock = -420;
  sodium_memzero(this->server_tx, crypto_kx_SESSIONKEYBYTES);
  sodium_memzero(this->server_rx, crypto_kx_SESSIONKEYBYTES);
}

int FS_Operator::init_read(
    int client_sock, char file_name_buf[250],
    unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES],
    unsigned char salt[crypto_pwhash_SALTBYTES],
    unsigned char server_rx[crypto_kx_SESSIONKEYBYTES]) {

  unsigned long long decrypted_file_name_length;
  SessionEncWrapper file_name_wrap = SessionEncWrapper(client_sock);

  if (file_name_wrap.unwrap(server_rx, FILE_NAME_BUF_SIZE,
                            reinterpret_cast<unsigned char *>(file_name_buf),
                            &decrypted_file_name_length) == 2) {
    std::cerr << "couldn't read file name, ABORT\n";
    return 1;
  }
  // decrypted file length will be NOT null terminated. so i need to null
  // terminate it before it leaves int_read

  if (decrypted_file_name_length + ext.length() > 255) {
    return 2;
  }

  file_name_buf[decrypted_file_name_length] = '\0';

  unsigned long long decrypted_header_length;
  SessionEncWrapper header_wrap = SessionEncWrapper(client_sock);
  header_wrap.unwrap(server_rx,
                     crypto_secretstream_xchacha20poly1305_HEADERBYTES, header,
                     &decrypted_header_length);

  std::cerr << "decrypted header length\n" << decrypted_header_length << "\n";

  SessionEncWrapper salt_wrap = SessionEncWrapper(client_sock);
  unsigned long long decrypted_salt_length;
  salt_wrap.unwrap(server_rx, crypto_pwhash_SALTBYTES, salt,
                   &decrypted_salt_length);

  std::cerr << "decrypted salt length\n" << decrypted_salt_length << "\n";

  return 0;
}

int FS_Operator::WTFS_Handler__Server() {

  // when doing multiple files and directories, this function could be called in
  // a separate thread perhaps for each file

  char file_name_buf[FILE_NAME_BUF_SIZE];

  unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
  unsigned char salt[crypto_pwhash_SALTBYTES];

  std::cerr << "prior to init_read\n";

  int init_read_err_code = init_read(this->client_sock, file_name_buf, header, salt, server_rx);

  if (init_read_err_code) {
    std::cerr << "init_read failed, aborting this WTFS Action | init_read returned " << init_read_err_code;
    return 1;
  }

  std::string file_name = file_name_buf;
  file_name.append(".enc");

  std::cerr << "this is file_name now after adding ext: " << file_name << "\n";

  std::ofstream file(file_name, std::ios::binary);

  file.write(reinterpret_cast<const char *>(header),
             crypto_secretstream_xchacha20poly1305_HEADERBYTES);
  file.write(reinterpret_cast<const char *>(salt), crypto_pwhash_SALTBYTES);

  std::cerr << "debug end\n";

  unsigned char read_buf[stream_chunk_size];
  size_t read_bytes;

  while (true) {
    SessionEncWrapper encrypted_data_wrap = SessionEncWrapper(client_sock);
    if (encrypted_data_wrap.get_data_length() == 0) {
      break; // we came across the last chunk already in the previous iteration
    }
    encrypted_data_wrap.write_to_file(file);
  };

  std::cerr << "returning 0 from the WTFS_Handler__Server\n";

  return 0;
}

int FS_Operator::RFFS_Handler__Server() {

  // send the whole file down the line

  char file_name_buf[FILE_NAME_BUF_SIZE];

  unsigned long long decrypted_file_name_length;

  SessionEncWrapper encrypted_file_name = SessionEncWrapper(client_sock);

  encrypted_file_name.unwrap(this->server_rx, FILE_NAME_BUF_SIZE,
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

    std::cout << "encrypting a chunk wee woo" << std::endl;

    file.read(reinterpret_cast<char *>(file_chunk), CHUNK_SIZE);

    unsigned long long file_chunk_len = file.gcount();

    std::cerr << "read file_chunk_len " << file_chunk_len << "\n";

    send(this->client_sock, file_chunk, file_chunk_len, 0);

  } while (!file.eof());

  return 0;
}
