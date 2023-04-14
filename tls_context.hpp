#ifndef _TLS_HANDSHAKE_TLS_CONTEXT
#define _TLS_HANDSHAKE_TLS_CONTEXT
#include <cstdint>
#include <optional>
#include <string>
#include <vector>
#include "./bytes.hpp"

class Keys {
public:

    bytes_t client_write_mac_key;
    bytes_t server_write_mac_key;
    bytes_t client_write_key;
    bytes_t server_write_key;
    bytes_t client_write_iv;
    bytes_t server_write_iv;

    Keys(
            const bytes_t& client_write_mac_key,
            const bytes_t& server_write_mac_key,
            const bytes_t& client_write_key,
            const bytes_t& server_write_key,
            const bytes_t& client_write_iv,
            const bytes_t& server_write_iv
    )
            : client_write_mac_key(client_write_mac_key)
            , server_write_mac_key(server_write_mac_key)
            , client_write_key(client_write_key)
            , server_write_key(server_write_key)
            , client_write_iv(client_write_iv)
            , server_write_iv(server_write_iv)
    {}
};

class TLSContext {
public:

    bytes_t client_random;
    bytes_t server_random;
    std::optional<bytes_t> premaster_secret;
    bytes_t master_secret;
    std::optional<Keys> keys;

    std::optional<bytes_t> server_public_key;

    bool client_hello_handshake_added;
    bool premaster_secret_packet_handshake_added;
    std::vector<bytes_t> handshake_packets;

    std::uint64_t i_seq;

    TLSContext();

    std::optional<std::string> hostname;
    virtual void set_hostname(const std::string& hn) { hostname = hn; }

    virtual bytes_t get_client_hello();
    virtual void eat_server_hello(const bytes_t&);
    virtual void eat_server_certificates(const bytes_t&);
    virtual void eat_server_done(const bytes_t&);

    virtual bytes_t get_client_key_exchange_packet();
    virtual bytes_t get_change_cipher_spec_packet();
    virtual bytes_t get_verify_data_packet();
    void eat_server_verify_data(const bytes_t&);
    
    virtual bytes_t encrypt_packet(std::uint8_t, const bytes_t&);
    virtual bytes_t encrypt_packet(const bytes_t&);
    virtual bytes_t decrypt_server_packet(const bytes_t&);

    virtual bytes_t get_close_packet();

protected:
    virtual void set_master_secret();
    virtual void set_keys();
};

#endif
