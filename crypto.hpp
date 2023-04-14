#ifndef _TLS_HANDSHAKE_CRYPTO
#define _TLS_HANDSHAKE_CRYPTO
#include "./bytes.hpp"

bytes_t sha1(const bytes_t& buffer);
bytes_t hmac_sha1(const bytes_t& buffer, const bytes_t& secret);
bytes_t sha256(const bytes_t& buffer);
bytes_t hmac_sha256(const bytes_t& buffer, const bytes_t& secret);
bytes_t rsa_encrypt(const bytes_t& key, const bytes_t& buffer);
bytes_t aes128_encrypt(const bytes_t& key, const bytes_t& iv, const bytes_t& buffer);
bytes_t aes128_decrypt(const bytes_t& key, const bytes_t& iv, const bytes_t& buffer);

#endif