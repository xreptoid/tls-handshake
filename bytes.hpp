#ifndef _TLS_HANDSHAKE_BYTES
#define _TLS_HANDSHAKE_BYTES
#include <cstdint>
#include <string>
#include <vector>

bool is_little_endian();

typedef std::vector<uint8_t> bytes_t;

bytes_t make_bytes(const std::string&);

bytes_t& operator+=(bytes_t&, const bytes_t&);
bytes_t operator+(const bytes_t&, const bytes_t&);

bytes_t generate_bytes(int n);
bytes_t number2bytes(std::uint64_t value, int size);
std::uint64_t bytes2number(const bytes_t&);
std::uint16_t bytes2uint16(const bytes_t&);
bytes_t subbytes(const bytes_t&, int from, int count);

#endif