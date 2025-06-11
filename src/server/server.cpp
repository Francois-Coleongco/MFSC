#include "../../include/auth.h"
#include "../../include/common/constants.h"
#include "../../include/read_write_handlers.h"
#include "../../include/server_logger.h"
#include <array>
#include <atomic>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <iostream>
#include <mutex>
#include <netinet/in.h>
#include <ostream>
#include <sodium/crypto_kx.h>
#include <sodium/crypto_pwhash.h>
#include <sodium/utils.h>
#include <sqlite3.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <thread>
#include <unistd.h>
#include <unordered_map>

const int ACK_SUC = 0;
const int ACK_FAIL = -1;
const int MAX_ZOMBIE_CONNS = 8;

enum CONN_TYPE { LIVE, ZOMBIE };

const int CONFUSION = -420;
const int READ_FROM_FILESYSTEM = 1;
const int WRITE_TO_FILESYSTEM = 2;

size_t total_connections = 0;
size_t live_connections = 0;

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

void clean_all(std::thread &log_thread, std::thread &kill_server_listener,
               std::thread &clean_intermittent_thread) {
  std::cerr << "starting clean_all\n";
  // destroy the active clients and zombie clients
  std::lock_guard<std::mutex> client_lock(clients_mutex);
  std::lock_guard<std::mutex> zombie_lock(zombie_clients_mutex);

  iter_clean_live(clients);
  iter_clean_zombie(zombie_clients);

  if (log_thread.joinable()) {
    log_thread.join();
    std::cerr << "completed log_thread\n";
  }
  if (kill_server_listener.joinable()) {
    kill_server_listener.join();
    std::cerr << "completed kill_server_listener\n";
  }
  if (clean_intermittent_thread.joinable()) {
    clean_intermittent_thread.join();
    std::cerr << "completed clean_intermittent_thread\n";
  }
}

int verify_credentials(sqlite3 *DB, std::string &username, int client_sock,
                       unsigned char *server_rx) {

  unsigned char decrypted_username[FILE_ENCRYPTED_CHUNK_SIZE];
  unsigned char decrypted_password[FILE_ENCRYPTED_CHUNK_SIZE];

  unsigned long long decrypted_username_len;
  unsigned long long decrypted_password_len;

  std::cerr << "starting username construction\n";
  SessionEncWrapper username_wrapper = SessionEncWrapper(client_sock);
  username_wrapper.unwrap(server_rx, FILE_ENCRYPTED_CHUNK_SIZE,
                          decrypted_username, &decrypted_username_len);

  std::cerr << "this was username " << decrypted_username << "\n";
  username = reinterpret_cast<char *>(decrypted_username);
  std::cerr << "starting password construction\n";
  SessionEncWrapper password_wrapper = SessionEncWrapper(client_sock);
  password_wrapper.unwrap(server_rx, FILE_ENCRYPTED_CHUNK_SIZE,
                          decrypted_password, &decrypted_password_len);
  std::cerr << "this was password " << decrypted_password << "\n";

  if (login(DB, reinterpret_cast<char *>(decrypted_username),
            decrypted_username_len,
            reinterpret_cast<char *>(decrypted_password),
            decrypted_password_len)) { // login implicitly zeroes out my
                                       // decrypted_username and
                                       // decrypted_password with sodium_memzero
    std::cerr << "returned 1 from login\n";
    return 1;
  }

  std::cerr << "made past login\n";

  return 0;
}

void handle_conn(sqlite3 *DB, int client_sock) {

  unsigned char server_pk[crypto_kx_PUBLICKEYBYTES],
      server_sk[crypto_kx_SECRETKEYBYTES];
  unsigned char server_rx[crypto_kx_SESSIONKEYBYTES],
      server_tx[crypto_kx_SESSIONKEYBYTES];

  if (server_crypt_gen(client_sock, server_pk, server_sk, server_rx,
                       server_tx)) {
    std::cerr << "couldn't gen keys :c" << std::endl;
    return;
  }

  // make sure the last character the 4095th index is not overwritten
  // cuz this is the null pointer for you cstring
  std::cerr << " WE ARE STARTING VERYIFY CREDSSS\n";

  std::string username;

  if (verify_credentials(DB, username, client_sock, server_rx)) {
    std::cerr << "couldn't verify creds, ignoring";
    send(client_sock, &ACK_FAIL, sizeof(int), 0);
    zombify(client_sock);
    return;
  } else {
    send(client_sock, &ACK_SUC, sizeof(int), 0); // successful login
  }

  unsigned char original_nonce[crypto_aead_chacha20poly1305_NPUBBYTES];

  randombytes_buf(original_nonce, crypto_aead_chacha20poly1305_NPUBBYTES);

  FS_Operator OP =
      FS_Operator(client_sock, username, server_rx, server_tx, original_nonce);

  bool perform_next = false;

  do {

    std::cerr << "asking for notice of new action\n";
    if (OP.receive_notice_of_new_action()) {
      std::cerr << "did not receive a notice of new action\n";
      perform_next = false;
      break;
    } else {
      perform_next = true;
    }

    int intent = OP.read_intent();

    if (intent == INVALID_READ_INTENT) {
      continue;
    }

    if (intent == READ_FROM_FILESYSTEM) {
      OP.RFFS_Handler__Server();
      std::cerr << "after RFFS_Handler\n";
    } else if (intent == WRITE_TO_FILESYSTEM) {
      OP.WTFS_Handler__Server();
      std::cerr << "after WTFS_Handler\n";
    } else {
      std::cerr << "invalid intention\n";
    }
  } while (perform_next);

  // end the loop here cuz zombify is after client ends communications

  zombify(client_sock);
}

void kill_server(std::atomic<bool> &server_alive, int server_sock) {
  std::cout << red << "kill the server by typing (q)\n" << norm;
  char switch_char;
  std::cin >> switch_char;
  if (switch_char == 'q') {
    server_alive = false;
  }
  std::cout << "server kill switch activated, server_alive is now "
            << server_alive << "\n";
  shutdown(server_sock, SHUT_RDWR);
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

  std::thread log_thread =
      std::thread(logger, std::ref(server_alive), std::ref(clients),
                  std::ref(zombie_clients), std::ref(live_connections),
                  std::ref(total_connections));
  std::thread cleanup_intermittent_thread =
      std::thread(cleanup_intermittent, std::ref(server_alive));
  std::thread kill_server_listener =
      std::thread(kill_server, std::ref(server_alive), server_sock);

  while (server_alive) {

    int client_sock = accept(server_sock, nullptr, nullptr);

    if (server_alive == false) {
      close(client_sock); // need to close manually here
      break;
    }

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

  std::cerr << "stopped accepting clients\n";

  sqlite3_close(DB);
  clean_all(log_thread, kill_server_listener, cleanup_intermittent_thread);

  // this should join the log_thread and
}
