#include "./crypto.hpp"
#include <stdexcept>
#include <cassert>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>

bytes_t sha1(const bytes_t& buffer) {
    std::uint8_t hash[SHA_DIGEST_LENGTH];
    SHA_CTX sha1;
    SHA1_Init(&sha1);
    SHA1_Update(&sha1, buffer.data(), buffer.size());
    SHA1_Final(hash, &sha1);
    return bytes_t(hash, hash + SHA_DIGEST_LENGTH);
}

bytes_t hmac_sha1(const bytes_t& buffer, const bytes_t& secret) {
    std::uint8_t hash[SHA_DIGEST_LENGTH];
    unsigned int len;
    HMAC(EVP_sha1(), secret.data(), secret.size(), buffer.data(), buffer.size(), hash, &len);
    assert(len == SHA_DIGEST_LENGTH);
    return bytes_t(hash, hash + SHA_DIGEST_LENGTH);
}

bytes_t sha256(const bytes_t& buffer) {
    std::uint8_t hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, buffer.data(), buffer.size());
    SHA256_Final(hash, &sha256);
    return bytes_t(hash, hash + SHA256_DIGEST_LENGTH);
}

bytes_t hmac_sha256(const bytes_t& buffer, const bytes_t& secret) {
    std::uint8_t hash[SHA256_DIGEST_LENGTH];
    unsigned int len;
    HMAC(EVP_sha256(), secret.data(), secret.size(), buffer.data(), buffer.size(), hash, &len);
    return bytes_t(hash, hash + SHA256_DIGEST_LENGTH);
}

bytes_t rsa_encrypt(const bytes_t& key, const bytes_t& buffer) {
    auto* key_data = key.data();
    X509* x509 = d2i_X509(NULL, &key_data, key.size());
    EVP_PKEY* pkey = X509_get_pubkey(x509);
    RSA* rsa = EVP_PKEY_get0_RSA(pkey);
    std::uint8_t encrypted_buf[1000]; // FIXME
    int encrypted_size = RSA_public_encrypt(
            buffer.size(),
            buffer.data(),
            encrypted_buf,
            rsa,
            RSA_PKCS1_PADDING
    );
    return bytes_t(encrypted_buf, encrypted_buf + encrypted_size);
}

/*
 * Copied from https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption
 */
int _aes128_encrypt(const unsigned char *plaintext, int plaintext_len, const unsigned char *key,
            const unsigned char *iv, unsigned char *ciphertext)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())) {
        throw std::runtime_error("_aes128_encrypt: Failed on EVP_CIPHER_CTX_new()");
    }

    /*
     * Initialise the encryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 128 bit AES (i.e. a 128 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv)) {
        throw std::runtime_error("_aes128_encrypt: Failed on EVP_EncryptInit_ex()");
    }

    /*
     * Disable padding
     */
    if(1 != EVP_CIPHER_CTX_set_padding(ctx, 0)) {
        throw std::runtime_error("_aes128_encrypt: Failed on EVP_CIPHER_CTX_set_padding()");
    }

    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) {
        throw std::runtime_error("_aes128_encrypt: Failed on EVP_EncryptUpdate()");
    }
    ciphertext_len = len;

    /*
     * Finalise the encryption. Further ciphertext bytes may be written at
     * this stage.
     */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
        throw std::runtime_error("_aes128_encrypt: Failed on EVP_EncryptFinal_ex()");
    }
    ciphertext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

int _aes128_decrypt(const unsigned char *ciphertext, int ciphertext_len, const unsigned char *key,
            const unsigned char *iv, unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int plaintext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())) {
        throw std::runtime_error("_aes128_decrypt: Failed on EVP_CIPHER_CTX_new()");
    }

    /*
     * Initialise the decryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 128 bit AES (i.e. a 128 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv)) {
        throw std::runtime_error("_aes128_decrypt: Failed on EVP_DecryptInit_ex()");
    }

    /*
     * Disable padding
     */
    if(1 != EVP_CIPHER_CTX_set_padding(ctx, 0)) {
        throw std::runtime_error("_aes128_encrypt: Failed on EVP_CIPHER_CTX_set_padding()");
    }

    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary.
     */
    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) {
        throw std::runtime_error("_aes128_decrypt: Failed on EVP_DecryptUpdate()");
    }
    plaintext_len = len;

    /*
     * Finalise the decryption. Further plaintext bytes may be written at
     * this stage.
     */
    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) {
        throw std::runtime_error("_aes128_decrypt: Failed on EVP_DecryptFinal_ex()");
    }
    plaintext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

bytes_t aes128_encrypt(const bytes_t& key, const bytes_t& iv, const bytes_t& buffer) {
    std::uint8_t buffer_encrypted[buffer.size() + (16 - buffer.size() % 16) % 16];
    int encrypted_size = _aes128_encrypt(buffer.data(), buffer.size(), key.data(), iv.data(), buffer_encrypted);
    return bytes_t(buffer_encrypted, buffer_encrypted + encrypted_size);
}

bytes_t aes128_decrypt(const bytes_t& key, const bytes_t& iv, const bytes_t& buffer) {
    std::uint8_t buffer_decrypted[buffer.size() + (16 - buffer.size() % 16) % 16];
    int decrypted_size = _aes128_decrypt(buffer.data(), buffer.size(), key.data(), iv.data(), buffer_decrypted);
    return bytes_t(buffer_decrypted, buffer_decrypted + decrypted_size);
}
