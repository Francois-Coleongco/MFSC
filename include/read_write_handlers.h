#include "../include/common/SessionEnc.h"
#include "../include/common/encryption_utils.h"
#include <sodium/crypto_kx.h>
#include <sodium/crypto_pwhash.h>
#include <sodium/crypto_secretstream_xchacha20poly1305.h>
#include <string>

const unsigned char MAX_FILE_SIZE =
    255; // since we are grabbing from storage, the max is 255

class FS_Operator {
  int client_sock;
  unsigned char server_rx[crypto_kx_SESSIONKEYBYTES];
  unsigned char server_tx[crypto_kx_SESSIONKEYBYTES];

private:
  int init_read(
      int client_sock, char file_name_buf[250],
      unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES],
      unsigned char salt[crypto_pwhash_SALTBYTES]);

public:
  int WTFS_Handler__Server(); // Write To File System Handler

  int RFFS_Handler__Server(); // Read From File System Handler

  FS_Operator(int client_sock,
              unsigned char server_rx[crypto_kx_SESSIONKEYBYTES],
              unsigned char server_tx[crypto_kx_SESSIONKEYBYTES]);
  ~FS_Operator();
};
