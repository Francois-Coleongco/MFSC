#include "read_write_handlers.h"

int init_read(
    int client_sock, std::string &file_name,
    unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES],
    unsigned char salt[crypto_pwhash_SALTBYTES],
    unsigned char server_rx[crypto_kx_SESSIONKEYBYTES]) {

  unsigned long long decrypted_file_name_length;
  SessionEncWrapper file_name_wrap = SessionEncWrapper(client_sock);
  file_name.resize(255);
  file_name_wrap.unwrap(server_rx,
                        reinterpret_cast<unsigned char *>(file_name.data()),
                        &decrypted_file_name_length);


  unsigned long long decrypted_header_length;
  SessionEncWrapper header_wrap = SessionEncWrapper(client_sock);
  header_wrap.unwrap(server_rx, header, &decrypted_header_length);

  std::cerr << "decrypted header length\n" << decrypted_header_length << "\n";

  SessionEncWrapper salt_wrap = SessionEncWrapper(client_sock);
  unsigned long long decrypted_salt_length;
  salt_wrap.unwrap(server_rx, header, &decrypted_salt_length);

  std::cerr << "decrypted salt length\n" << decrypted_salt_length << "\n";

  return 0;
}

int WTFS_Handler__Server(int client_sock,
                         unsigned char server_rx[crypto_kx_SESSIONKEYBYTES]) {
  // when doing multiple files and directories, this function could be called in
  // a separate thread perhaps for each file

  std::string file_name;
  unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
  unsigned char salt[crypto_pwhash_SALTBYTES];

  std::cerr << "prior to init_read\n";

  init_read(client_sock, file_name, header, salt, server_rx);

  std::cerr << "this is file_name before appending " << file_name << "\n";
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
