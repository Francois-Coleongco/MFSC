#include "../../include/authed_entry.h"
#include "../../include/common/SessionEnc.h"
#include "../../include/common/constants.h"
#include "../../include/common/encryption_utils.h"
#include <cassert>
#include <iostream>
#include <netinet/in.h>
#include <sodium/crypto_aead_chacha20poly1305.h>
#include <sodium/crypto_box.h>
#include <sodium/crypto_kx.h>
#include <sodium/crypto_pwhash.h>
#include <sodium/crypto_secretstream_xchacha20poly1305.h>
#include <sodium/randombytes.h>
#include <sodium/utils.h>
#include <sys/socket.h>
#include <unistd.h>

// intentions
const int ACK_SUC = 0;
const int ACK_FAIL = -1;

const int CONFUSION = -420;
const int READ_FROM_FILESYSTEM = 1;
const int WRITE_TO_FILESYSTEM = 2;

template <typename T> void get_stuff(T &stuff_holder) {
  do {
    std::cin.clear();
    std::cin.ignore();
    std::cin >> stuff_holder;
  } while (std::cin.fail());
}

int send_credentials(int client_sock, unsigned char *client_tx,
                     std::string &username, std::string &password) {

  std::cout << "enter username:" << std::endl;
  std::cin >> username;
  std::cout << "enter password:" << std::endl;
  std::cin >> password;

  // encrypt the username and password and send it over to the server and wait
  //
  // for a resposne

  unsigned char username_ciphertext[username.length() + 1 +
                                    crypto_aead_chacha20poly1305_ABYTES];
  unsigned long long username_ciphertext_len;

  unsigned char password_ciphertext[password.length() + 1 +
                                    crypto_aead_chacha20poly1305_ABYTES];

  unsigned long long password_ciphertext_len;

  unsigned char username_nonce[crypto_aead_chacha20poly1305_NPUBBYTES];
  unsigned char password_nonce[crypto_aead_chacha20poly1305_NPUBBYTES];

  if (encrypt_stream_buffer(client_tx, username_nonce,
                            reinterpret_cast<unsigned char *>(username.data()),
                            username.length() + 1, username_ciphertext,
                            &username_ciphertext_len)) {
    std::cerr
        << "couldn't encrypt error in encrypt_and_send_stream_buffer_with_nonce"
        << std::endl;
  }

  if (encrypt_stream_buffer(client_tx, password_nonce,
                            reinterpret_cast<unsigned char *>(password.data()),
                            password.length() + 1, password_ciphertext,
                            &password_ciphertext_len)) {
    std::cerr
        << "couldn't encrypt error in encrypt_and_send_stream_buffer_with_nonce"
        << std::endl;
  }

  int received_username = -1;

  send(client_sock, username_nonce, crypto_aead_chacha20poly1305_NPUBBYTES, 0);

  send(client_sock, password_nonce, crypto_aead_chacha20poly1305_NPUBBYTES, 0);

  send(client_sock, username_ciphertext, username_ciphertext_len,
       0); // username
  recv(client_sock, &received_username, sizeof(received_username), 0);

  int received_password = -1;

  send(client_sock, password_ciphertext, password_ciphertext_len, 0);

  recv(client_sock, &received_password, sizeof(received_password), 0);

  int auth_stat = -1;

  recv(client_sock, &auth_stat, sizeof(auth_stat), 0);

  if (auth_stat == -1) {
    std::cout << "you sir/madam are not authenticated." << std::endl;
    exit(-1);
  }

  sodium_memzero(username.data(), username.size());

  return 0;
}

int send_intention(unsigned char client_tx[crypto_kx_SESSIONKEYBYTES],
                   int client_sock, int intent) {

  SessionEncWrapper intent_wrap = SessionEncWrapper(
      reinterpret_cast<unsigned char *>(&intent), sizeof(intent), client_tx);

  intent_wrap.send_data_length(client_sock);
  intent_wrap.send_nonce(client_sock);
  intent_wrap.send_data(client_sock);

  return 0;
}

int RFFS_Handler(Comms_Agent *CA, Receiver_Agent &RA, int client_sock,
                 std::string &password) {

  std::string file_name;
  std::cout << "enter file name to grab from server:\n";

  std::cin >> file_name;

  return 0;
}

int WTFS_Handler(Comms_Agent *CA, Sender_Agent &SA, int client_sock,
                 std::string &password) {
  std::cerr << "made it here in WTFS_Handler\n";

  std::cout << "enter file name to send to server:\n";

  std::string file_name;

  get_stuff(file_name);

  if (SA.encrypt_and_send_to_server(file_name) != 0) {
    std::cerr << "error in encrypt_and_send_to_server\n";
  }

  return 0;
}

int authed_comms(int client_sock,
                 unsigned char client_tx[crypto_kx_SESSIONKEYBYTES],
                 unsigned char client_rx[crypto_kx_SESSIONKEYBYTES],
                 std::string &username, std::string &password) {

  Comms_Agent CA = Comms_Agent(client_tx, client_rx, client_sock);
  /// loop from here to the end of the function depending on what the user
  /// syas they want to do. aka if they wish to complete another action, don't
  /// deconstruct the CA, save it for future. REMEMBER in creating CA you
  /// destroyed the original keys. you have no way of communication without
  /// them.

  char perform_next = 'n';

  do {
    if (CA.notify_server_of_action(NEW_ACTION)) {
      std::cerr << "couldn't notify server of new user action\n";
      break;
    };

    std::cout << "enter your intention (1 == read || 2 == write)" << std::endl;

    int intention = CONFUSION;

    get_stuff(intention);

    // when we eventually make the program capable of handling multiple files
    // concurrently, we will need to spawn threads that create their own SA or
    // RA
    Sender_Agent SA = Sender_Agent(&CA, password);
    Receiver_Agent RA = Receiver_Agent(&CA);

    if (intention == CONFUSION) {
      return -1;
    }

    if (intention == READ_FROM_FILESYSTEM) {
      send_intention(CA.get_client_tx(), client_sock, intention);
      if (RFFS_Handler(&CA, RA, client_sock, password)) {
        std::cerr << "failed reading from file system\n";
      }
    } else if (intention == WRITE_TO_FILESYSTEM) {
      send_intention(CA.get_client_tx(), client_sock, intention);
      if (WTFS_Handler(&CA, SA, client_sock, password)) {
        std::cerr << "failed writing to file system\n";
      };
    } else {
      std::cerr << "invalid intention\n";
    }

    std::cout << "perform another action?\n";
    std::cin >> perform_next;
  } while (perform_next == 'y' || perform_next == 'Y');

  CA.notify_server_of_action(NO_ACTION);

  // already memzeroed the username during send_credentials
  sodium_memzero(password.data(), password.size());
  return 0;
}

int main() {

  int client_sock = socket(AF_INET, SOCK_STREAM, 0);
  sockaddr_in server_address;
  server_address.sin_family = AF_INET;
  server_address.sin_port = htons(8080);
  server_address.sin_addr.s_addr = INADDR_ANY;

  int conn_stat = connect(client_sock, (struct sockaddr *)&server_address,
                          sizeof(server_address));

  unsigned char client_pk[crypto_kx_PUBLICKEYBYTES],
      client_sk[crypto_kx_SECRETKEYBYTES];
  unsigned char client_rx[crypto_kx_SESSIONKEYBYTES],
      client_tx[crypto_kx_SESSIONKEYBYTES];

  if (client_crypt_gen(client_sock, client_pk, client_sk, client_rx,
                       client_tx)) {
    std::cerr << "error generating keys :(" << std::endl;
    return 1;
  }

  std::cerr << std::endl;

  std::string username;
  std::string password;

  int intention = CONFUSION;

  if (send_credentials(client_sock, client_tx, username, password)) {
    std::cerr << "exiting login_handle" << std::endl;
    return 2;
  }

  authed_comms(client_sock, client_tx, client_rx, username, password);

} // this will contain the rest of the follwoing after
// no signup, this is only done by the admin of the server who can add
// themselves to the sql db
