project(tls-handshake)
cmake_minimum_required(VERSION 3.10)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

if(APPLE)
    set(OPENSSL_ROOT_DIR /usr/local/opt/openssl@1.1)
endif()

find_package(OpenSSL REQUIRED)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_FLAGS_RELEASE "-O3")

add_executable(
        tls-handshake
        main.cpp
        bytes.cpp
        tls_connection.cpp
        tls_context.cpp
        crypto.cpp
        tcp.cpp
)
target_link_libraries(
        tls-handshake
        OpenSSL::Crypto
)
