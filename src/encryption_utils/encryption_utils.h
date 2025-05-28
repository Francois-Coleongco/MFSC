#include <iostream>
#include <netinet/in.h>
#include <sodium/crypto_aead_chacha20poly1305.h>
#include <sodium/crypto_kx.h>
#include <sodium/crypto_secretstream_xchacha20poly1305.h>
#include <sodium/randombytes.h>

#pragma once

const size_t stream_chunk_size = 4096 + crypto_secretstream_xchacha20poly1305_ABYTES;

int encrypt_stream_buffer(
    unsigned char tx[crypto_kx_SESSIONKEYBYTES],
    unsigned char nonce[crypto_aead_chacha20poly1305_NPUBBYTES],
    unsigned char *msg_box, unsigned long long message_len,
    unsigned char *ciphertext, unsigned long long *ciphertext_len);

