#include <cstdint>
#include <vector>

typedef std::vector<uint8_t> bytes_t;

bytes_t& operator+=(bytes_t&, const bytes_t&);
bytes_t operator+(const bytes_t&, const bytes_t&);
bytes_t generate_bytes(int n);
