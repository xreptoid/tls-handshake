#ifndef _TLS_HANDSHAKE_TCP
#define _TLS_HANDSHAKE_TCP
#include <iostream>
#include "./bytes.hpp"

class TCPConnection {
public:
    
    TCPConnection(const std::string& host, int port);

    void connect();
    void close();
    void send(const bytes_t&);
    bytes_t recv();

protected:
    std::string host;
    int port;
    int sock = 0;
};

#endif