#include <iostream>
#include <string>

int main() {
  std::string ext = ".enc";
  char file_name_buf[250] = "123"; // includes null byte

  std::string file_name = file_name_buf;
  file_name.append(ext);

  std::cout << file_name << std::endl;

  // if (file_name.length() check goes here)
}
