#include "../encryption_utils/SessionEnc.h"
#include "../encryption_utils/encryption_utils.h"
#include "auth/auth.h"
#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <functional>
#include <iostream>
#include <mutex>
#include <netinet/in.h>
#include <ostream>
#include <sodium/crypto_kx.h>
#include <sodium/utils.h>
#include <sqlite3.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <thread>
#include <unistd.h>
#include <unordered_map>

const size_t chunk_size = 4096;
const int ACK_SUC = 0;
const int ACK_FAIL = -1;
const int MAX_ZOMBIE_CONNS = 1;

const int CONFUSION = -420;
const int READ_FROM_FILESYSTEM = 1;
const int WRITE_TO_FILESYSTEM = 2;

int total_connections = 0;
int live_connections = 0;

struct Client_Info {
  std::thread client_thread;
};

std::unordered_map<int, Client_Info> clients;
std::unordered_map<int, Client_Info> zombie_clients;
std::mutex clients_mutex;
std::mutex zombie_clients_mutex;

void zombify(int client_sock) {
  std::cout << "zombify called" << std::endl;
  // i dont think i need ot check if it exists because if cleanup was called,
  // the handle_conn func has a live thread and therefore Client_Info associated
  // with it
  std::lock_guard<std::mutex> zomb_lock(zombie_clients_mutex);
  std::lock_guard<std::mutex> client_lock(clients_mutex);
  zombie_clients.insert(
      {client_sock, std::move(clients.find(client_sock)->second)});
  close(client_sock);
  clients.erase(client_sock);
  --live_connections;
}

void iter_clean_live(std::unordered_map<int, Client_Info> &map) {
  for (auto &pair : map) {
    std::cerr << "processing client " << pair.first << "\n";
    if (pair.second.client_thread.joinable()) {
      std::cout << "joined thread\n";
      pair.second.client_thread.join();
      std::cout << "completed thread\n";
      close(pair.first);
    }
  }
}
void iter_clean_zombie(std::unordered_map<int, Client_Info> &map) {
  for (auto &pair : map) {
    std::cerr << "processing client " << pair.first << "\n";
    if (pair.second.client_thread.joinable()) {
      std::cout << "joined thread\n";
      pair.second.client_thread.join();
      std::cout << "completed thread\n";
    }
  }
}

void cleanup_intermittent(std::atomic<bool> &server_alive) {
  // this will just clean up the zombie clients in std::unordered_map<int,
  // Client_Info> zombie_clients;
  while (server_alive) {
    if (zombie_clients.size() < MAX_ZOMBIE_CONNS) {
      std::this_thread::sleep_for(std::chrono::seconds(2));
      continue;
    }
    std::cerr << "cleanup intermittent called\n";
    std::unique_lock<std::mutex> zombie_lock(zombie_clients_mutex);
    std::cerr << "zombie client count before loop " << zombie_clients.size()
              << "\n";

    iter_clean_zombie(zombie_clients);

    zombie_clients.clear();

    zombie_lock.unlock();
    std::this_thread::sleep_for(std::chrono::seconds(1));
    std::cerr << "exited cleanup_intermittent\n";
  }
}

void clean_all() {
  // destroy the active clients and zombie clients
  std::lock_guard<std::mutex> client_lock(clients_mutex);
  std::lock_guard<std::mutex> zombie_lock(zombie_clients_mutex);

  iter_clean_live(clients);
  iter_clean_zombie(zombie_clients);
}

int crypt_gen(int client_sock, unsigned char *server_pk,
              unsigned char *server_sk, unsigned char *server_rx,
              unsigned char *server_tx) {

  /* Generate the server's key pair */
  crypto_kx_keypair(server_pk, server_sk);
  std::cerr << "this is server_pk" << std::endl;

  for (int i = 0; i < crypto_kx_PUBLICKEYBYTES; ++i) {
    printf("%c", server_pk[i]);
  }

  std::cout << std::endl;

  send(client_sock, server_pk, crypto_kx_PUBLICKEYBYTES, 0);

  // receive client_pk from client

  unsigned char client_pk[crypto_kx_PUBLICKEYBYTES];

  int crypto_bytes_read =
      recv(client_sock, client_pk, crypto_kx_PUBLICKEYBYTES, 0);

  std::cout << "ON THE SERVER cryptobytesread: " << crypto_bytes_read
            << std::endl;

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
    return 1;
  }

  std::cerr << "DIDNT BAIL WE HAVE VALID KEYSSS YAYYY" << std::endl;

  return 0;
}

int verify_credentials(sqlite3 *DB, int client_sock, unsigned char *server_rx) {

  std::array<char, chunk_size> username_buffer{0};
  std::array<char, chunk_size> password_buffer{0};

  unsigned char username_nonce[crypto_aead_chacha20poly1305_NPUBBYTES];

  unsigned char password_nonce[crypto_aead_chacha20poly1305_NPUBBYTES];

  // int username_nonce_bytes = recv(client_sock, username_nonce,
  //                                 crypto_aead_chacha20poly1305_NPUBBYTES, 0);
  //
  int username_nonce_bytes = recv(client_sock, username_nonce,
                                  crypto_aead_chacha20poly1305_NPUBBYTES, 0);

  int password_nonce_bytes = recv(client_sock, password_nonce,
                                  crypto_aead_chacha20poly1305_NPUBBYTES, 0);

  int username_bytes_read = recv(client_sock, &username_buffer, chunk_size, 0);

  send(client_sock, &ACK_SUC, sizeof(ACK_SUC), 0);

  int password_bytes_read = recv(client_sock, &password_buffer, chunk_size, 0);
  std::cerr << "read password YIPPIEEE this was how many bytes it was: "
            << password_bytes_read << std::endl;
  send(client_sock, &ACK_SUC, sizeof(ACK_SUC), 0);

  if (username_bytes_read <= 0 || password_bytes_read <= 0) {
    std::cerr << "one of these username_bytes_read or password_bytes_read "
                 "returned a value less than or equal to 0"
              << std::endl;
    return 1;
  }

  char decrypted_username[username_bytes_read];

  unsigned long long decrypted_username_len;

  if (crypto_aead_chacha20poly1305_decrypt(
          reinterpret_cast<unsigned char *>(decrypted_username),
          &decrypted_username_len, NULL,
          reinterpret_cast<unsigned char *>((username_buffer.data())),
          username_bytes_read, NULL, 0, username_nonce, server_rx) != 0) {
    std::cerr << "error decrypting the username" << std::endl;
  } else {
    std::cerr << "SUCCESSFUL <USERNAME> DECRYPTION ==== " << decrypted_username
              << std::endl;
  }

  char decrypted_password[password_bytes_read];

  unsigned long long decrypted_password_len;

  if (crypto_aead_chacha20poly1305_decrypt(
          reinterpret_cast<unsigned char *>(decrypted_password),
          &decrypted_password_len, NULL,
          reinterpret_cast<unsigned char *>(password_buffer.data()),
          password_bytes_read, NULL, 0, password_nonce, server_rx) != 0) {
    std::cerr << "error decrypting the password" << std::endl;
  } else {
    std::cerr << "password cipher" << password_buffer.data() << "password"
              << std::endl;
    std::cerr << "SUCCESSFUL <PASSWORD> DECRYPTION" << decrypted_password
              << std::endl;
  }

  if (login(DB, decrypted_username, decrypted_username_len, decrypted_password,
            decrypted_password_len)) { // login implicitly zeroes out my
                                       // decrypted_username and
                                       // decrypted_password with sodium_memzero
    std::cerr << "returned 1 from login\n";
    return 1;
  }

  std::cerr << "made past login\n";

  return 0;

  // reads from recv the ENCRYPTED username and password and decrypts it and
  // checks against the database using auth.h funcs
}

// void forward_to_all(std::array<char, chunk_size> buffer, int sender) {
//
//   for (int client_sock : clients) {
//
//     if (client_sock == sender) {
//       continue;
//     }
//
//     std::cout << "trying to forward buffer to client_sock: " << client_sock
//               << std::endl;
//
//     int bytes_sent = send(client_sock, buffer.data(), chunk_size, 0);
//
//     if (bytes_sent < 0) {
//       std::cerr << "couldn't forward to this client: " << client_sock
//                 << std::endl;
//     }
//   }
// }

void print_conns(std::unordered_map<int, Client_Info> &map) {
  for (const auto &pair : map) {
    std::cerr << "fd: " << pair.first << "\n";
  }
}

void print_border_top() {
  size_t len =
      20; // might make this an argument in the future if u care enough lol
  for (size_t i = 0; i < len; ++i) {
    std::cerr << "-";
  }
}

void logger(std::atomic<bool> &server_alive) {
  while (server_alive) {
    print_border_top();
    std::cerr << "CURRENT CONNECTIONS =>" << live_connections;
    print_border_top();
    std::cerr << "LIVE CLIENTS =>" << clients.size() << "\n";
    print_conns(clients);
    print_border_top();
    std::cerr << "ZOMBIE CLIENTS =>" << zombie_clients.size() << "\n";
    print_conns(zombie_clients);
    print_border_top();
    std::this_thread::sleep_for(std::chrono::seconds(4));
  }
}

template <typename T> int get_stream_item_size(int client_sock, T *size) {
  return recv(client_sock, size, sizeof(size), 0);
}

int init_read(int client_sock, std::string &file_name,
              unsigned char server_rx[crypto_kx_SESSIONKEYBYTES]) {

  unsigned long long decrypted_file_name_length;
  SessionEncWrapper file_name_wrap = SessionEncWrapper(client_sock);
  file_name_wrap.unwrap(server_rx, file_name_wrap.get_nonce(),
                        reinterpret_cast<unsigned char *>(file_name.data()),
                        &decrypted_file_name_length);

  std::cerr << "decrypted file_name length\n"
            << decrypted_file_name_length << "\n";

  unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
  unsigned long long decrypted_header_length;
  SessionEncWrapper header_wrap = SessionEncWrapper(client_sock);
  header_wrap.unwrap(server_rx, header_wrap.get_nonce(), header,
                     &decrypted_header_length);

  std::cerr << "decrypted header length\n" << decrypted_header_length << "\n";

  unsigned char salt[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
  SessionEncWrapper salt_wrap = SessionEncWrapper(client_sock);
  unsigned long long decrypted_salt_length;
  salt_wrap.unwrap(server_rx, salt_wrap.get_nonce(), header,
                   &decrypted_salt_length);

  std::cerr << "decrypted salt length\n" << decrypted_salt_length << "\n";

  return 0;
}

int WTFS_Handler__Server(int client_sock,
                         unsigned char server_rx[crypto_kx_SESSIONKEYBYTES]) {
  // when doing multiple files and directories, this function could be called in
  // a separate thread perhaps for each file

  std::string file_name;

  std::cerr << "prior to init_read\n";
  init_read(client_sock, file_name, server_rx);

  std::cerr << "debug end\n";

  // std::ofstream file(file_name, std::ios::binary);
  //
  // unsigned char read_buf[chunk_size];
  // size_t bytes_to_read;
  // size_t read_bytes;
  //
  // do {
  //   bytes_to_read = recv(client_sock, &bytes_to_read, sizeof(bytes_to_read),
  //   0); read_bytes = recv(client_sock, read_buf, chunk_size, 0);
  //   // obviously gonna have to write the buffer after the recv to a file on
  //   the
  //   // server. need to figure out how to structure the file system.
  //   std::cerr << "read_bytes is " << read_bytes << "\n";
  //   size_t written_ack = send(client_sock, &ACK_SUC, sizeof(ACK_SUC), 0);
  // } while (bytes_to_read != 0);

  return 0;
}

void handle_conn(sqlite3 *DB, int client_sock) {

  unsigned char server_pk[crypto_kx_PUBLICKEYBYTES],
      server_sk[crypto_kx_SECRETKEYBYTES];
  unsigned char server_rx[crypto_kx_SESSIONKEYBYTES],
      server_tx[crypto_kx_SESSIONKEYBYTES];

  if (crypt_gen(client_sock, server_pk, server_sk, server_rx, server_tx)) {
    std::cerr << "couldn't gen keys :c" << std::endl;
  }

  std::cerr << "this is server_tx" << std::endl;

  for (int i = 0; i < crypto_kx_SESSIONKEYBYTES; ++i) {
    printf("%c", server_tx[i]);
  }

  std::cerr << std::endl;

  std::array<char, chunk_size> buffer{0};

  // make sure the last character the 4095th index is not overwritten
  // cuz this is the null pointer for you cstring
  if (verify_credentials(DB, client_sock, server_rx)) {
    std::cerr << "couldn't verify creds, ignoring";
    send(client_sock, &ACK_FAIL, sizeof(int), 0);
    zombify(client_sock);
    return;
  }

  send(client_sock, &ACK_SUC, sizeof(int), 0);

  // need to move code starting from here
  std::array<unsigned char, crypto_aead_chacha20poly1305_NPUBBYTES>
      intention_nonce;

  recv(client_sock, intention_nonce.data(),
       crypto_aead_chacha20poly1305_NPUBBYTES, 0);

  int intent;

  unsigned long long intent_len;

  std::array<unsigned char, sizeof(intent)> intent_arr;

  std::array<unsigned char,
             sizeof(intent) + crypto_aead_chacha20poly1305_ABYTES>
      intention_cipher;

  recv(client_sock, intention_cipher.data(),
       sizeof(intent) + crypto_aead_chacha20poly1305_ABYTES, 0);

  if (crypto_aead_chacha20poly1305_decrypt(
          intent_arr.data(), &intent_len, NULL,
          reinterpret_cast<unsigned char *>((intention_cipher.data())),
          intention_cipher.size(), NULL, 0, intention_nonce.data(),
          server_rx) != 0) {
    std::cerr << "error decrypting intention" << std::endl;

    // loop again letting client know there was an error and to try again
  }

  std::memcpy(&intent, intent_arr.data(), intent_len);

  std::cerr << "user's intention was " << intent << std::endl;
  std::cerr << "SUCCESSFUL <INTENTION> DECRYPTION" << std::endl;

  if (intent == READ_FROM_FILESYSTEM) {
    // to be implemented
  } else if (intent == WRITE_TO_FILESYSTEM) {
    WTFS_Handler__Server(client_sock, server_rx);
  }

  zombify(client_sock);
}

int main() {

  std::atomic<bool> server_alive = true;
  sqlite3 *DB;

  if (initialize_server(&DB)) {
    std::cerr << "couldn't open db" << std::endl;
    return 1;
  }

  int server_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

  if (server_sock == -1) {
    std::cout << "Failed to create socket descriptor. " << strerror(errno)
              << "\n";
    return 1;
  } else {
    std::cout << "success making server_sock\n";
  }
  sockaddr_in server_address;

  server_address.sin_family = AF_INET;

  server_address.sin_port = htons(8080);

  server_address.sin_addr.s_addr = INADDR_ANY; // 127.0.0.1
  std::cout << "starting bind\n";

  int opt = 1;
  if (setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) <
      0) {
    std::cerr << "setsockopt failed: " << strerror(errno) << std::endl;
    close(server_sock);
    return 1;
  }

  int bind_stat = bind(server_sock, (struct sockaddr *)&server_address,
                       sizeof(server_address));

  if (bind_stat == -1) {
    std::cout << "Failed to bind socket. " << strerror(errno) << std::endl;
    close(server_sock);
    return 1;
  }

  if (listen(server_sock, 5) < 0) {
    std::cout << "server could not listen" << std::endl;
    close(server_sock);
  }

  std::cout << "accepting\n";

  std::thread log_thread = std::thread(logger, std::ref(server_alive));
  std::thread cleanup_intermittent_thread =
      std::thread(cleanup_intermittent, std::ref(server_alive));
  // std::thread kill_server_listener = std::thread(kill_server);

  while (server_alive) {

    int client_sock = accept(server_sock, nullptr, nullptr);

    std::cout << "made another socket: " << client_sock << "\n";

    if (client_sock < 0) {
      std::cerr << "Failed to accept connection" << std::endl;
      continue;
    }

    std::lock_guard<std::mutex> client_lock(clients_mutex);
    clients[client_sock].client_thread =
        std::thread(handle_conn, DB, client_sock);

    ++total_connections;
    ++live_connections;
  }

  clean_all(); // this should join the log_thread and
               // cleanup_intermittent_thread
}
