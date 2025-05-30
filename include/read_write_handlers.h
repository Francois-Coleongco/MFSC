#include <sodium/crypto_pwhash.h>
#include <sodium/crypto_kx.h>
#include <sodium/crypto_secretstream_xchacha20poly1305.h>
#include "../include/common/encryption_utils.h"
#include "../include/common/SessionEnc.h"


#include <string>

int init_read(
    int client_sock, std::string &file_name,
    unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES],
    unsigned char salt[crypto_pwhash_SALTBYTES],
    unsigned char server_rx[crypto_kx_SESSIONKEYBYTES]);

int WTFS_Handler__Server(int client_sock,
                         unsigned char server_rx[crypto_kx_SESSIONKEYBYTES]);
