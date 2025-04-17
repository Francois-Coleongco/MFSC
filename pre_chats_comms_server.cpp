#include <cerrno>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <netinet/in.h>
#include <sodium/crypto_kx.h>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>
#include <vector>

// key exchange, credential send, and credential validation and response

const size_t buffer_size = 4096;

std::vector<std::thread> threads;
std::vector<int> clients;
int numConnections = 0;

void handle_conn(int client_sock) {
  unsigned char server_pk[crypto_kx_PUBLICKEYBYTES],
      server_sk[crypto_kx_SECRETKEYBYTES];
  unsigned char server_rx[crypto_kx_SESSIONKEYBYTES],
      server_tx[crypto_kx_SESSIONKEYBYTES];

  /* Generate the server's key pair */
  crypto_kx_keypair(server_pk, server_sk);
  std::cerr << "this is server_pk" << std::endl;

  for (int i = 0; i < crypto_kx_PUBLICKEYBYTES; ++i) {
    printf("%c", server_pk[i]);
  }

  std::cout << std::endl;

  // send server_pk to client

  send(client_sock, server_pk, crypto_kx_PUBLICKEYBYTES, 0);

  // receive client_pk from client

  unsigned char client_pk[crypto_kx_PUBLICKEYBYTES];

  recv(client_sock, client_pk, crypto_kx_PUBLICKEYBYTES, 0);

  std::cerr << "this is client_pk" << std::endl;
  for (int i = 0; i < crypto_kx_PUBLICKEYBYTES; ++i) {
    printf("%c", client_pk[i]);
  }

  std::cout << std::endl;

  /* Prerequisite after this point: the client's public key must be known by
   * the server */

  /* Compute two shared keys using the client's public key and the server's
     secret key. server_rx will be used by the server to receive data from
     the client, server_tx will be used by the server to send data to the
     client. */

  if (crypto_kx_server_session_keys(server_rx, server_tx, server_pk, server_sk,
                                    client_pk) != 0) {
    std::cerr << "BAILED" << std::endl;
    /* Suspicious client public key, bail out */
  }

  std::cerr << "DIDNT BAIL WE HAVE VALID KEYSSS YAYYY" << std::endl;

  // get shared secrets
  //
  // start listening for creds
  //
  // validate creds
  //
  // respond with status
}

int main() {
  int s_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

  if (s_sock == -1) {
    std::cout << "Failed to create socket descriptor. " << strerror(errno)
              << "\n";
    return 1;
  } else {
    std::cout << "success making s_sock\n";
  }
  sockaddr_in server_address;

  server_address.sin_family = AF_INET;

  server_address.sin_port = htons(8888);

  server_address.sin_addr.s_addr = INADDR_ANY; // 127.0.0.1
  std::cout << "starting bind\n";

  int opt = 1;
  if (setsockopt(s_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) == -1) {
    std::cout << "Failed to set SO_REUSEADDR. " << strerror(errno) << std::endl;
    close(s_sock);
    return 1;
  }

  int bind_stat =
      bind(s_sock, (struct sockaddr *)&server_address, sizeof(server_address));

  if (bind_stat == -1) {
    std::cout << "Failed to bind socket. " << strerror(errno) << std::endl;
    close(s_sock);
    return 1;
  }

  if (listen(s_sock, 5) < 0) {
    std::cout << "server could not listen" << std::endl;
    close(s_sock);
  }

  while (true) {

    int client_sock = accept(s_sock, nullptr, nullptr);
    std::cout << "made another socket: " << client_sock << "\n";

    if (client_sock < 0) {
      std::cerr << "Failed to accept connection" << std::endl;
      continue;
    }

    threads.push_back(std::thread(handle_conn, client_sock));
    clients.push_back(client_sock);
    ++numConnections;

    threads.back().detach();
  }
}
