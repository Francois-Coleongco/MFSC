// everything in this file contains resources for the server after a user is
// authenticated.
#include <fstream>
#include <iostream>
#include <sys/socket.h>

const int chunk_size = 4096;

class Sender {

  int client_sock;
  char *buffer; // buffer capacity is always 4096
  size_t
      size; // the size here refers to the amount of the buffer that is filled

private:
  int send_size() {
    int sent_bytes =
        send(this->client_sock, &(this->size), sizeof(this->size), 0);
    // just sends the size
    return sent_bytes;
  }

  int send_buffer() {
    // just sends the buffer
    int sent_bytes = send(this->client_sock, buffer, this->size, 0);
    return sent_bytes;
  }

public:
  // add functionality for directories later
  int fill_and_send(std::string &file_name) { // this takes in a file containing
                                              // already encrypted data.

    std::ifstream file(file_name, std::ios::binary);
    // the file that is passed must be an already encrypted file done by another
    // func;

    if (!file) {
      std::cerr << "couldn't open the file" << std::endl;
      return -1;
    }

    while (file) {
      file.read(this->buffer, chunk_size);
      this->size = file.gcount();
      this->send_size(); // always send size of buffer before the actual buffer
      this->send_buffer();
    }

    // start by sending the size, then send the encrypted bytes
    return 0;
  }

  Sender(int client_sock) : client_sock{client_sock}, buffer(new char[4096]) {};

  ~Sender() { delete[] this->buffer; }
  // copy constructor is kinda weird for here, same as move, i dont think we
  // will need multiple Senders for the same user
};

class Receiver {

  int client_sock;
  char *buffer; // buffer capacity is always 4096
  size_t
      size; // the size here refers to the amount of the buffer that is filled
};
