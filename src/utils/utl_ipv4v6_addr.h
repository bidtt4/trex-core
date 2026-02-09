#ifndef UTL_IPV4V6_ADDR_H
#define UTL_IPV4V6_ADDR_H

#include <array>
#include <cstdint>
#include <string>

struct ipv4v6_addr {
    enum class Version {
        V4,
        V6
    };

    union {
        uint32_t v4;
        std::array<uint16_t, 8> v6;
    } addr;
    Version version;

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

    static uint32_t distance(const ipv4v6_addr& lhs, const ipv4v6_addr& rhs);
    static uint32_t num_ips(const ipv4v6_addr& lhs, const ipv4v6_addr& rhs);
    static ipv4v6_addr from_str(const char* str);
    static ipv4v6_addr ipv4(uint32_t addr);
    static ipv4v6_addr force_ipv6(const ipv4v6_addr& rhs);
    static ipv4v6_addr ipv6_be(uint16_t* addr);
};

#endif // UTL_IPV4V6_ADDR_H
