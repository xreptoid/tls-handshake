#include "./tls_context.hpp"
#include <iostream>
#include "./crypto.hpp"

TLSContext::TLSContext() {
    client_random = generate_bytes(32);
    premaster_secret = bytes_t{0x03, 0x03} + generate_bytes(46);
    client_hello_handshake_added = false;
    premaster_secret_packet_handshake_added = false;
    i_seq = 0;
}

bytes_t TLSContext::get_client_hello() {
    bytes_t header;
    // Content type: Handshake
    header += {0x16};
    // TLS 1.2
    header += {0x03, 0x03};
    // length = 512
    header += number2bytes(512, 2);

    bytes_t data;
    data += {0x01};
    // length = 512-4
    data += number2bytes(512 - 4, 3);
    // TLS 1.2
    data += {0x03, 0x03};

    data += client_random;

    // session ID length
    data += {0x00};
    // ciphers suitres length = 2 (but 1)
    data += {0x00, 0x02};
    // TLS_RSA_WITH_AES_128_CBC_SHA
    data += {0x00, 0x2F};
    // number of compression methods=1, compression method=null
    data += {0x01, 0x00};

    auto extensions_length = 512 - data.size() - 2;
    data += number2bytes(extensions_length, 2);

    // renegotiation_info
    data += {0xFF, 0x01};
    data += number2bytes(1, 2);
    data += number2bytes(0, 1);

    if (hostname.has_value()) {
        // server name type=host_name
        bytes_t server_name_meta = bytes_t{0x00} + number2bytes(hostname->size(), 2) + make_bytes(*hostname);
        server_name_meta = number2bytes(server_name_meta.size(), 2) + server_name_meta;
        server_name_meta = number2bytes(server_name_meta.size(), 2) + server_name_meta;
        data += {0x00, 0x00};
        data += server_name_meta;
    }

    data += {0x00, 0x15}; //padding
    auto padding_size = 512 - data.size() - 2;
    data += number2bytes(padding_size, 2); // padding size
    for (int i = 0; i < padding_size; ++i) {
        data += {0x00};
    }
    data = header + data;
    if (!client_hello_handshake_added) {
        handshake_packets.push_back(subbytes(data, 5, data.size() - 5));
        client_hello_handshake_added = true;
    }
    return data;
}

void TLSContext::eat_server_hello(const bytes_t& server_hello) {
    server_random = subbytes(server_hello, 6, 32);
    handshake_packets.push_back(server_hello);
}

std::vector<bytes_t> get_certificates(const bytes_t& packet) {
    std::vector<bytes_t> certs;
    int pos = 7;
    while (pos < packet.size()) {
        int len = bytes2number(subbytes(packet, pos, 3));
        certs.push_back(subbytes(packet, pos + 3, len));
        pos += len + 3;
    }
    return certs;
}

void TLSContext::eat_server_certificates(const bytes_t& certs_packet) {
    auto certs = get_certificates(certs_packet);
    if (certs.empty()) {
        throw std::runtime_error("TLSContext::eat_server_certificates: no certs given");
    }
    server_public_key = certs[0];
    set_master_secret();
    set_keys();
    handshake_packets.push_back(certs_packet);
}

void TLSContext::eat_server_done(const bytes_t& server_done) {
    handshake_packets.push_back(server_done);
}

bytes_t prf(const bytes_t& secret, const bytes_t& seed, int len) {
    bytes_t res;
    std::vector<bytes_t> a;
    a.push_back(seed);
    while (res.size() < len) {
        a.push_back(hmac_sha256(a.back(), secret));
        res += hmac_sha256(a.back() + seed, secret);
    }
    return subbytes(res, 0, len);
}

void TLSContext::set_master_secret() {
    if (!premaster_secret.has_value()) {
        throw std::runtime_error("TLSContext::set_master_secret(): no premaster_secret");
    }
    master_secret = prf(*premaster_secret, make_bytes("master secret") + client_random + server_random, 48);
}

bytes_t TLSContext::get_client_key_exchange_packet() {
    if (!server_public_key.has_value()) {
        throw std::runtime_error("TLSContext::get_client_key_exchange_packet(): no server_public_key");
    }
    if (!premaster_secret.has_value()) {
        throw std::runtime_error("TLSContext::get_client_key_exchange_packet(): no premaster_secret");
    }

    auto premaster_secret_encrypted = rsa_encrypt(*server_public_key, *premaster_secret);
    bytes_t packet = number2bytes(premaster_secret_encrypted.size(), 2) + premaster_secret_encrypted;
    // 0x10 - Client Key exchange
    packet = bytes_t{0x10} + number2bytes(packet.size(), 3) + packet;
    // 0x16 - Handshake message; 0x0303 - TLSv1.2
    packet = bytes_t{0x16} + bytes_t{0x03, 0x03} + number2bytes(packet.size(), 2) + packet;

    if (!premaster_secret_packet_handshake_added) {
        handshake_packets.push_back(subbytes(packet, 5, packet.size() - 5));
        premaster_secret_packet_handshake_added = true;
    }
    return packet;
}

bytes_t TLSContext::get_change_cipher_spec_packet() {
    bytes_t packet = {
        // change cipher spec
        0x14,
        // TLS v1.2
        0x03, 0x03};
    // length=1
    packet += number2bytes(1, 2);
    // spec=1
    packet += {0x01};
    return packet;
}

bytes_t TLSContext::get_verify_data_packet() {
    if (!keys.has_value()) {
        std::cout << "TLSContext::get_verify_data_packet: no keys" << std::endl;
    }
    bytes_t handshake_sum;
    for (const auto& packet: handshake_packets) {
        handshake_sum += packet;
    }
    auto handshake_hash = sha256(handshake_sum);
    auto verify_data = bytes_t{0x14, 0x00, 0x00, 0x0C} + prf(master_secret, make_bytes("client finished") + handshake_hash, 12);
    return encrypt_packet(0x16, verify_data);
}

void TLSContext::eat_server_verify_data(const bytes_t& packet) {
    // nope
}

bytes_t TLSContext::encrypt_packet(std::uint8_t content_type, const bytes_t& data) {
    bytes_t seq = number2bytes(i_seq++, 8);
    bytes_t rechdr = {content_type, 0x03, 0x03};
    bytes_t datalen = number2bytes(data.size(), 2);
    bytes_t hash = hmac_sha1(seq + rechdr + datalen + data, keys->client_write_mac_key);
    bytes_t data_with_meta = data + hash;

    std::uint8_t padding = 16 - data_with_meta.size() % 16; // 1..16
    std::uint8_t padding_val = padding - 1; // 0x00..0x0F
    for (int i = 0; i < padding; ++i) {
        data_with_meta += {padding_val};
    }

    bytes_t enc_iv = generate_bytes(16);
    auto data_encrypted = enc_iv + aes128_encrypt(keys->client_write_key, enc_iv, data_with_meta);
    bytes_t packet = rechdr;
    packet += number2bytes(data_encrypted.size(), 2);
    packet += data_encrypted;
    return packet;
}

bytes_t TLSContext::encrypt_packet(const bytes_t& data) {
    return encrypt_packet(0x17, data);
}

bytes_t TLSContext::decrypt_server_packet(const bytes_t& packet) {
    bytes_t enc_iv = subbytes(packet, 0, 16);
    bytes_t enc_data = subbytes(packet, 16, packet.size() - 16);
    auto data_with_meta = aes128_decrypt(keys->server_write_key, enc_iv, enc_data);
    if (data_with_meta.empty()) {
        return data_with_meta;
    }
    auto padding = static_cast<std::uint8_t>(data_with_meta.back()) + 1;
    return subbytes(data_with_meta, 0, data_with_meta.size() - padding - 20); // hash size = 20 bytes
}

bytes_t TLSContext::get_close_packet() {
    return encrypt_packet(0x15, {0x01, 0x00});
}

void TLSContext::set_keys() {
    bytes_t data = prf(master_secret, make_bytes("key expansion") + server_random + client_random, 104);
    keys = Keys(
        subbytes(data, 0, 20),
        subbytes(data, 20, 20),
        subbytes(data, 40, 16),
        subbytes(data, 56, 16),
        subbytes(data, 72, 16),
        subbytes(data, 88, 16)
    );
}