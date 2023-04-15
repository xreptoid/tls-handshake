#include <iostream>
#include <optional>
#include <string>
#include <vector>
#include "./tls_connection.hpp"

int main(int argc, char** argv) {
    std::string host = "99.84.56.223";
    std::optional<std::string> hostname = "api.binance.com";
    int port = 443;

    auto ctx = TLSContext();
    if (hostname.has_value()) {
        ctx.set_hostname(*hostname);
    }
    auto con = TLSConnection(&ctx, host, port);
    con.connect();
    std::cout << "connected" << std::endl;

    std::string req = "GET /api/v3/time HTTP/1.1\r\nHost: api.binance.com\r\nAccept: */*\r\n\r\n";
    con.send(req);
    auto resp = con.recv()[0];
    std::cout << resp << std::endl;

    return 0;
}