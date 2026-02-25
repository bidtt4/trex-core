#ifndef UTL_IPV4V6_ADDR_H
#define UTL_IPV4V6_ADDR_H

#include <array>
#include <cstdint>
#include <string>
#include "utl_ipv6_hextets.h"

struct ipv4v6_addr {
    enum class Version {
        V4,
        V6
    };

    Version version;
    // addr is stored as little endian
    union {
        struct {
            uint32_t v4;
            std::array<uint32_t, 3> pad;
        };
        ipv6_hextets v6;
    } addr;

    bool operator==(const ipv4v6_addr& rhs) const;
    bool operator!=(const ipv4v6_addr& rhs) const;
    bool operator<(const ipv4v6_addr& rhs) const;
    bool operator>(const ipv4v6_addr& rhs) const;
    bool operator<=(const ipv4v6_addr& rhs) const;
    bool operator>=(const ipv4v6_addr& rhs) const;

    ipv4v6_addr& operator+=(int64_t rhs);
    ipv4v6_addr operator+(int64_t rhs) const;
    ipv4v6_addr& operator-=(int64_t rhs);
    ipv4v6_addr operator-(int64_t rhs) const;

    ipv4v6_addr& operator+=(const ipv4v6_addr& rhs);
    ipv4v6_addr operator+(const ipv4v6_addr& rhs) const;

    std::string to_str() const;
    std::string to_hex_str() const;
    bool set_from_str(const char* str);

    static uint32_t modulo(const ipv4v6_addr& lhs, uint32_t rhs);
    static uint32_t distance(const ipv4v6_addr& lhs, const ipv4v6_addr& rhs);
    static uint32_t range_size(const ipv4v6_addr& lhs, const ipv4v6_addr& rhs);
    static ipv4v6_addr from_str(const char* str);
    static ipv4v6_addr ipv4_be(uint32_t addr);
    static ipv4v6_addr ipv4_le(uint32_t addr);
    static ipv4v6_addr ipv6_compatible(const ipv4v6_addr& rhs);
    static ipv4v6_addr ipv6_be(uint16_t* addr);
};

template<>
struct std::hash<ipv4v6_addr> {
    size_t operator()(const ipv4v6_addr& addr) const noexcept {
        if (addr.version == ipv4v6_addr::Version::V4) {
            return std::hash<uint32_t>{}(addr.addr.v4);
        }
        size_t h = 0;
        for (uint16_t v : addr.addr.v6) {
            h ^= std::hash<uint16_t>{}(v) + 0x9e3779b97f4a7c15ULL + (h << 6) + (h >> 2);
        }
        return h;
    }
};

#endif // UTL_IPV4V6_ADDR_H
