cmake_minimum_required(VERSION 3.10)

project(MFSC LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")

find_package(SQLite3 REQUIRED)
find_package(Sodium REQUIRED)

add_library(common_lib STATIC
    src/encryption_utils/SessionEnc.cpp
    src/encryption_utils/encryption_utils.cpp
)

target_include_directories(common_lib PUBLIC 
    include/common
    ${sodium_INCLUDE_DIR}
)

target_link_libraries(common_lib PRIVATE sodium)

add_executable(server 
    src/server/server.cpp 
    src/server/auth.cpp 
    src/server/read_write_handlers.cpp
    src/server/server_logger.cpp
)

target_include_directories(server PUBLIC include)

target_link_libraries(server PRIVATE
    common_lib
    SQLite::SQLite3
)

add_executable(client 
    src/client/client.cpp 
    src/client/authed_entry.cpp
)

target_include_directories(client PUBLIC include)

target_link_libraries(client PRIVATE
    common_lib
)
