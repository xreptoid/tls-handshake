#include <iostream>
#include <optional>
#include <string>
#include <vector>
#include "./bytes.hpp"

bytes_t generate_client_random() {
    return generate_bytes(32);
}

bytes_t get_client_hello_packet(const std::string& client_random, const std::optional<std::string>& hostname) {
    return bytes_t();
} 

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cout << "Usage: handshake HOST [HOSTNAME]" << std::endl;
        return 1;
    }

    auto host = std::string(argv[1]);
    std::optional<std::string> hostname;
    if (argc > 2) {
        hostname = argv[2];
    }

    return 0;
}