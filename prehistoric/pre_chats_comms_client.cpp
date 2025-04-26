#include <array>
#include <cassert>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <netinet/in.h>
#include <ostream>
#include <sodium/crypto_kx.h>
#include <sys/socket.h>
#include <unistd.h>

int main() {

  const size_t buffer_size = 4096;

  int client_sock = socket(AF_INET, SOCK_STREAM, 0);
  sockaddr_in server_address;
  server_address.sin_family = AF_INET;
  server_address.sin_port = htons(8888);
  server_address.sin_addr.s_addr = INADDR_ANY;

  int conn_stat = connect(client_sock, (struct sockaddr *)&server_address,
                          sizeof(server_address));

  unsigned char client_pk[crypto_kx_PUBLICKEYBYTES],
      client_sk[crypto_kx_SECRETKEYBYTES];
  unsigned char client_rx[crypto_kx_SESSIONKEYBYTES],
      client_tx[crypto_kx_SESSIONKEYBYTES];

  /* Generate the client's key pair */
  crypto_kx_keypair(client_pk, client_sk);

	std::cerr << "this is client_pk" << std::endl;

  for (int i = 0; i < crypto_kx_PUBLICKEYBYTES; ++i) {
    printf("%c", client_pk[i]);
  }

  std::cout << std::endl;


  send(client_sock, client_pk, crypto_kx_PUBLICKEYBYTES, 0);

  /* Prerequisite after this point: the server's public key must be known by the
   * client */

  /* Compute two shared keys using the server's public key and the client's
     secret key. client_rx will be used by the client to receive data from the
     server, client_tx will be used by the client to send data to the server. */

  unsigned char server_pk[crypto_kx_PUBLICKEYBYTES];

  recv(client_sock, server_pk, crypto_kx_PUBLICKEYBYTES, 0);

	std::cerr << "this is server_pk" << std::endl;

  for (int i = 0; i < crypto_kx_PUBLICKEYBYTES; ++i) {
    printf("%c", server_pk[i]);
  }

  std::cout << std::endl;

  if (crypto_kx_client_session_keys(client_rx, client_tx, client_pk, client_sk,
                                    server_pk) != 0) {
		std::cerr << "BAILED SUS KEYS" << std::endl;
    /* Suspicious server public key, bail out */
  }

	std::cerr << "DIDNT BAIL WE HAVE VALID KEYSSS YAYAYYYYY" << std::endl;
}
