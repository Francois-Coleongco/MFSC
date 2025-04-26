
// everything in this file contains resources for the server after a user is
// authenticated.
#include <fstream>
#include <iostream>
#include <sys/socket.h>

// need header guardss

const int chunk_size = 4096;

class Sender {

  int client_sock;
  char *buffer; // buffer capacity is always 4096
  size_t
      size; // the size here refers to the amount of the buffer that is filled

private:
  int send_buffer();
  int send_size();

public:
  // add functionality for directories later
  int fill_and_send(std::string &file_name);
  Sender(int client_sock);

  ~Sender();
  // copy constructor is kinda weird for here, same as move, i dont think we
  // will need multiple Senders for the same user
};

class Receiver {

  int client_sock;
  char *buffer; // buffer capacity is always 4096
  size_t
      size; // the size here refers to the amount of the buffer that is filled
};
