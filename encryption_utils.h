#include <iostream>
#include <sodium/crypto_aead_chacha20poly1305.h>
#include <sodium/randombytes.h>
#include <netinet/in.h>

int encrypt_stream_buffer(unsigned char *client_tx, unsigned char *msg_box,
                          int message_len, unsigned char *ciphertext,
                          unsigned long long *ciphertext_len, int client_sock);
