#include "./bytes.hpp"
#include <algorithm>
#include <random>

bool is_little_endian() {
    int num = 1;
    return *reinterpret_cast<char*>(&num) == 1;
}

bytes_t make_bytes(const std::string& s) {
    return bytes_t(s.c_str(), s.c_str() + s.size());
}

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

bytes_t number2bytes(std::uint64_t value, int size) {
    auto* arr = reinterpret_cast<std::uint8_t*>(&value);
    auto buf = bytes_t(arr, arr + size);
    if (is_little_endian()) {
        return bytes_t(buf.rbegin(), buf.rend());
    }
    return buf;
}

std::uint64_t bytes2number(const bytes_t& bytes) {
    auto temp = bytes;
    if (is_little_endian()) {
        temp = bytes_t(bytes.rbegin(), bytes.rend());
    }
    for (int i = 0; i < 8 - bytes.size(); ++i) {
        temp += {0x00};
    }
    return *reinterpret_cast<const std::uint64_t*>(temp.data());
}

bytes_t subbytes(const bytes_t& bytes, int from, int count) {
    count = std::min(count, static_cast<int>(bytes.size()) - from);
    return bytes_t(bytes.begin() + from, bytes.begin() + from + count);
}
