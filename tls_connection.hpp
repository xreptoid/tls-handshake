#ifndef _TLS_HANDSHAKE_TLS_CONNECTION
#define _TLS_HANDSHAKE_TLS_CONNECTION
#include <string>
#include <vector>
#include "./tls_context.hpp"
#include "./tcp.hpp"

class TLSConnection {
public:

    TLSConnection(
            TLSContext* ctx,
            const std::string& host,
            int port);
    virtual ~TLSConnection();

    virtual void connect();
    virtual void close();
    virtual void send(const bytes_t&);
    virtual void send(const std::string&);
    virtual std::vector<bytes_t> recv_bytes();
    virtual std::vector<std::string> recv();

protected:
    std::string host;
    int port;
    TCPConnection* tcp_con = NULL;
    TLSContext* ctx;

    virtual std::vector<bytes_t> recv_packets();
};
#endif