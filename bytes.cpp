#include "./bytes.hpp"
#include <random>

bytes_t& operator+=(bytes_t& a, const bytes_t& b) {
    a.insert(a.end(), b.begin(), b.end());
    return a;
}

bytes_t operator+(const bytes_t& a, const bytes_t& b) {
    bytes_t r;
    r += a;
    r += b;
    return r;
}

bytes_t generate_bytes(int n) {
    std::vector<std::uint8_t> r(n);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dist(0x00, 0xFF);
    for (std::size_t i = 0; i < n; ++i) {
        r[i] = static_cast<std::uint8_t>(dist(gen));
    }
    return r;
}
