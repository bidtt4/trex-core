#include "utl_ipv4v6_addr.h"
#include "utl_ipv6_hextets.h"

#include <arpa/inet.h>
#include <array>
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <endian.h>
#include <limits>
#include <string>

static __uint128_t hextets_to_uint128(const ipv6_hextets& addr) {
    __uint128_t result = 0;
    for (int i = 0; i < 8; i++) {
        result = (result << 16) | addr[i];
    }
    return result;
}

static ipv6_hextets uint128_to_hextets(__uint128_t addr) {
    ipv6_hextets result = {};
    for (int i = 7; i >= 0; i--) {
        result[i] = static_cast<uint16_t>(addr & 0xFFFF);
        addr >>= 16;
    }
    return result;
}

static uint32_t ipv6_distance(const ipv6_hextets& a, const ipv6_hextets& b) {
    __uint128_t big_a = hextets_to_uint128(a);
    __uint128_t big_b = hextets_to_uint128(b);
    __uint128_t diff = (big_a > big_b) ? (big_a - big_b) : (big_b - big_a);
    if (diff > std::numeric_limits<uint32_t>::max()) {
        // Legacy trex-core code stores results in uint32_t, so the behavior will be more correct
        // if we just return maximum possible value instead of random number in lower 32 bits
        return std::numeric_limits<uint32_t>::max();
    }
    return static_cast<uint32_t>(diff);
}

bool ipv4v6_addr::operator==(const ipv4v6_addr& rhs) const {
    if (version != rhs.version) {
        return false;
    }
    if (version == ipv4v6_addr::Version::V4) {
        return addr.v4 == rhs.addr.v4;
    } else {
        return memcmp(addr.v6.data(), rhs.addr.v6.data(), 16) == 0;
    }
}

bool ipv4v6_addr::operator!=(const ipv4v6_addr& rhs) const {
    return !(*this == rhs);
}

bool ipv4v6_addr::operator<(const ipv4v6_addr& rhs) const {
    if (version != rhs.version) {
        return version < rhs.version;
    }
    if (version == ipv4v6_addr::Version::V4) {
        return addr.v4 < rhs.addr.v4;
    } else {
        return hextets_to_uint128(addr.v6) < hextets_to_uint128(rhs.addr.v6);
    }
}

bool ipv4v6_addr::operator>(const ipv4v6_addr& rhs) const {
    if (version != rhs.version) {
        return version > rhs.version;
    }
    if (version == ipv4v6_addr::Version::V4) {
        return addr.v4 > rhs.addr.v4;
    } else {
        return hextets_to_uint128(addr.v6) > hextets_to_uint128(rhs.addr.v6);
    }
}

bool ipv4v6_addr::operator<=(const ipv4v6_addr& rhs) const {
    return *this < rhs || *this == rhs;
}

bool ipv4v6_addr::operator>=(const ipv4v6_addr& rhs) const {
    return *this > rhs || *this == rhs;
}

ipv4v6_addr ipv4v6_addr::operator+(int64_t rhs) const {
    ipv4v6_addr result = *this;
    result += rhs;
    return result;
}

ipv4v6_addr& ipv4v6_addr::operator+=(int64_t rhs) {
    if (version == ipv4v6_addr::Version::V4) {
        addr.v4 += rhs;
    } else {
        addr.v6 = uint128_to_hextets(hextets_to_uint128(addr.v6) + rhs);
    }
    return *this;
}

ipv4v6_addr ipv4v6_addr::operator-(int64_t rhs) const {
    ipv4v6_addr result = *this;
    result -= rhs;
    return result;
}

ipv4v6_addr& ipv4v6_addr::operator-=(int64_t rhs) {
    if (version == ipv4v6_addr::Version::V4) {
        addr.v4 -= rhs;
    } else {
        addr.v6 = uint128_to_hextets(hextets_to_uint128(addr.v6) - rhs);
    }
    return *this;
}

ipv4v6_addr& ipv4v6_addr::operator+=(const ipv4v6_addr& rhs) {
    assert(version == rhs.version);
    if (version == ipv4v6_addr::Version::V4) {
        addr.v4 += rhs.addr.v4;
        return *this;
    }
    auto lhs_int = hextets_to_uint128(addr.v6);
    auto rhs_int = hextets_to_uint128(rhs.addr.v6);
    addr.v6 = uint128_to_hextets(lhs_int + rhs_int);
    return *this;
}

ipv4v6_addr ipv4v6_addr::operator+(const ipv4v6_addr& rhs) const {
    ipv4v6_addr result = *this;
    result += rhs;
    return result;
}

uint32_t ipv4v6_addr::distance(const ipv4v6_addr& lhs, const ipv4v6_addr& rhs) {
    assert(lhs.version == rhs.version);
    if (lhs.version == ipv4v6_addr::Version::V4) {
        return lhs.addr.v4 > rhs.addr.v4 ? lhs.addr.v4 - rhs.addr.v4 : rhs.addr.v4 - lhs.addr.v4;
    } else {
        return ipv6_distance(lhs.addr.v6, rhs.addr.v6);
    }
}

uint32_t ipv4v6_addr::range_size(const ipv4v6_addr& lhs, const ipv4v6_addr& rhs) {
    auto dist = distance(lhs, rhs);
    return dist < UINT32_MAX ? dist + 1 : UINT32_MAX;
}

ipv4v6_addr ipv4v6_addr::from_str(const char* str) {
    ipv4v6_addr result = {};
    if (!result.set_from_str(str)) {
        fprintf(stderr, "Error: Bad IP address %s. Exiting.", str);
        std::abort();
    }
    return result;
}

std::string ipv4v6_addr::to_str() const {
    std::array<char, INET6_ADDRSTRLEN> buf = {};
    if (version == ipv4v6_addr::Version::V4) {
        uint32_t network_order = htobe32(addr.v4);
        inet_ntop(AF_INET, &network_order, buf.data(), buf.size());
    } else {
        auto network_order = ipv6_to_be(addr.v6);
        inet_ntop(AF_INET6, network_order.data(), buf.data(), buf.size());
    }
    return std::string(buf.data());
}

std::string ipv4v6_addr::to_hex_str() const {
    std::array<char, 40> buf = {};
    if (version == ipv4v6_addr::Version::V4) {
        snprintf(buf.data(), buf.size(), "%08x", addr.v4);
    } else {
        snprintf(buf.data(), buf.size(), "%04x%04x%04x%04x%04x%04x%04x%04x",
                addr.v6[0], addr.v6[1], addr.v6[2], addr.v6[3],
                addr.v6[4], addr.v6[5], addr.v6[6], addr.v6[7]);
    }
    return std::string(buf.data());
}

ipv4v6_addr ipv4v6_addr::ipv4_be(uint32_t addr) {
    return ipv4v6_addr::ipv4_le(be32toh(addr));
}

ipv4v6_addr ipv4v6_addr::ipv4_le(uint32_t addr) {
    return {
        .version = ipv4v6_addr::Version::V4,
        .addr = { .v4 = addr }
    };
}

ipv4v6_addr ipv4v6_addr::ipv6_compatible(const ipv4v6_addr& rhs) {
    if (rhs.version == ipv4v6_addr::Version::V6) {
        return rhs;
    }
    ipv4v6_addr result = {};
    result.addr.v6 = {};
    result.addr.v6[6] = rhs.addr.v4 >> 16;
    result.addr.v6[7] = rhs.addr.v4 & 0xFFFF;
    result.version = ipv4v6_addr::Version::V6;
    return result;
}

ipv4v6_addr ipv4v6_addr::ipv6_be(uint16_t* addr) {
    ipv4v6_addr result = {};
    result.version = ipv4v6_addr::Version::V6;
    result.addr.v6 = ipv6_to_le(addr);
    return result;
}

bool ipv4v6_addr::set_from_str(const char* str) {
    int rc = inet_pton(AF_INET, str, &addr.v4);
    if (rc) {
        version = ipv4v6_addr::Version::V4;
        addr.v4 = be32toh(addr.v4);
        return true;
    }
    rc = inet_pton(AF_INET6, str, addr.v6.data());
    if (rc) {
        version = ipv4v6_addr::Version::V6;
        addr.v6 = ipv6_to_le(addr.v6);
        return true;
    }
    return false;
}
