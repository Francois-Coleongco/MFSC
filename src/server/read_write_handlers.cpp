#include "../../include/read_write_handlers.h"

const unsigned char FILE_NAME_BUF_SIZE = 250; // remove 5 from 255 because that is reserved for the .enc extension (null byte included)
const std::string ext = ".enc";

int init_read(
    int client_sock, char file_name_buf[250],
    unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES],
    unsigned char salt[crypto_pwhash_SALTBYTES],
    unsigned char server_rx[crypto_kx_SESSIONKEYBYTES]) {

  unsigned long long decrypted_file_name_length;
  SessionEncWrapper file_name_wrap = SessionEncWrapper(client_sock);

  file_name_wrap.unwrap(server_rx, FILE_NAME_BUF_SIZE,
                        reinterpret_cast<unsigned char *>(file_name_buf),
                        &decrypted_file_name_length);
  // decrypted file length will be NOT null terminated. so i need to null terminate it before it leaves int_read

  if (decrypted_file_name_length + ext.length() > 255) {
    return 1;
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

int WTFS_Handler__Server(int client_sock,
                         unsigned char server_rx[crypto_kx_SESSIONKEYBYTES]) {
  // when doing multiple files and directories, this function could be called in
  // a separate thread perhaps for each file

  char file_name_buf[FILE_NAME_BUF_SIZE];

  unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
  unsigned char salt[crypto_pwhash_SALTBYTES];

  std::cerr << "prior to init_read\n";

  if (init_read(client_sock, file_name_buf, header, salt, server_rx)) {
    return 1;
  }

  std::string file_name = file_name_buf;
  file_name.append(".enc");

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
