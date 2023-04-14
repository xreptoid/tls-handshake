#include <iostream>
#include <vector>
#include <string>
#include "./tls_connection.hpp"

TLSConnection::TLSConnection(
    TLSContext* ctx,
    const std::string& host,
    int port
)
        : ctx(ctx)
        , host(host)
        , port(port)
{}

TLSConnection::~TLSConnection() {
    delete tcp_con;
}

std::vector<bytes_t> parse_packets(const bytes_t& data) {
    int i_next_packet = 0;
    std::vector<bytes_t> packets;
    while (i_next_packet < data.size()) {
        auto len = bytes2number(subbytes(data, i_next_packet + 3, 2));
        packets.push_back(subbytes(data, i_next_packet + 5, len));
        i_next_packet += 5 + len;
    }
    return packets;
}

std::vector<bytes_t> parse_packets2(const bytes_t& data) {
    int i_next_packet = 0;
    std::vector<bytes_t> packets;
    while (i_next_packet < data.size()) {
        auto len = bytes2number(subbytes(data, i_next_packet + 3, 2));
        packets.push_back(subbytes(data, i_next_packet, 5 + len));
        i_next_packet += 5 + len;
    }
    return packets;
}

void TLSConnection::connect() {
    if (tcp_con) {
        std::cout << "TLSConnection::connect: already connected" << std::endl;
    }
    tcp_con = new TCPConnection(host, port);
    tcp_con->connect();

    tcp_con->send(ctx->get_client_hello());

    std::vector<bytes_t> packets1;
    while (packets1.size() < 3) {
        auto new_packets = recv_packets();
        if (new_packets.empty()) {
            throw std::runtime_error("failed to recv hello");
        }
        packets1.insert(packets1.end(), new_packets.begin(), new_packets.end());
    }
    ctx->eat_server_hello(packets1[0]);
    ctx->eat_server_certificates(packets1[1]);
    ctx->eat_server_done(packets1[2]);

    bytes_t packet;
    packet += ctx->get_client_key_exchange_packet();
    packet += ctx->get_change_cipher_spec_packet();
    packet += ctx->get_verify_data_packet();
    tcp_con->send(packet);

    std::vector<bytes_t> packets2;
    while (packets2.size() < 2) {
        auto new_packets = recv_packets();
        if (new_packets.empty()) {
            throw std::runtime_error("failed to recv finish");
        }
        packets2.insert(packets2.end(), new_packets.begin(), new_packets.end());
    }
    ctx->eat_server_verify_data(packets2[1]);
}

void TLSConnection::close() {
    if (tcp_con) {
        tcp_con->send(ctx->get_close_packet());
        tcp_con->close();
        delete tcp_con;
    }
}

std::vector<bytes_t> TLSConnection::recv_packets() {
    bytes_t data;
    int i_next_packet = 0;
    std::vector<bytes_t> packets;
    while (true) {
        auto buf = tcp_con->recv();
        if (buf.empty()) {
            break;
        }
        data += buf;
        bool is_partial = false;
        while (i_next_packet < data.size()) {
            auto len = bytes2number(subbytes(data, i_next_packet + 3, 2));
            int i_start = i_next_packet + 5;
            int i_fin_excluding = i_start + len;
            if (i_fin_excluding > data.size()) {
                is_partial = true;
                break;
            }
            packets.push_back(subbytes(data, i_start, len));
            i_next_packet += 5 + len;
        }
        if (!is_partial) {
            break;
        }
    }
    return packets;
}

void TLSConnection::send(const bytes_t& data) {
    tcp_con->send(ctx->encrypt_packet(data));
}

std::vector<bytes_t> TLSConnection::recv() {
    auto packets_encrypted = parse_packets(tcp_con->recv());
    std::vector<bytes_t> packets;
    for (const auto& packet_encrypted: packets_encrypted) {
        packets.push_back(ctx->decrypt_server_packet(packet_encrypted));
    }
    return packets;
}
