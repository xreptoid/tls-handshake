#include "./tcp.hpp"
#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

TCPConnection::TCPConnection(
        const std::string& host,
        int port
)
        : host(host)
        , port(port)
{}

void TCPConnection::connect() {
    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock < 0) {
        std::cout << "Error on creating socket (err=" << errno << ", " << strerror(errno) << ")" << std::endl;
        return;
    }

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = inet_addr(host.c_str());
    sa.sin_port = htons(port);
    socklen_t socklen = sizeof(sa);

    auto connect_ret = ::connect(sock, (struct sockaddr*)&sa, socklen);
    if (connect_ret) {
        std::cout << "Error connecting to server (err=" << errno << ", " << strerror(errno) << ")" << " " << host << std::endl;
        return;
    }
}

void TCPConnection::close() {
    ::close(sock);
}

void TCPConnection::send(const bytes_t& packet) {
    if (::send(sock, packet.data(), packet.size(), 0) < 0) {
        std::cout << "TCPConnection(" << host << ")::send: " << "sending failed" << std::endl;
    }
}

bytes_t TCPConnection::recv() {
    int buf_size = 1 << 16;
    std::uint8_t buf[buf_size];
    bytes_t recv_data;
    while (true) {
        int recv_size;
        if ((recv_size = ::recv(sock, buf, buf_size, 0)) < 0) {
            perror("reading stream message");
            break;
        }
        if (recv_size == 0) {
            std::cout << "recv_size = 0" << std::endl;
            break;
        }
        recv_data += bytes_t(buf, buf + recv_size);
        if (recv_size < buf_size) {
            break;
        }
    }
    return recv_data;
}
