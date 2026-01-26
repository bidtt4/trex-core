#include <cstring>
#include <endian.h>

#include "utl_ipv6_hextets.h"

ipv6_hextets ipv6_to_be(const ipv6_hextets& ipv6) {
    ipv6_hextets hextets = ipv6;
    for (auto& hextet : hextets) {
        hextet = htobe16(hextet);
    }
    return hextets;
}

ipv6_hextets ipv6_to_le(const ipv6_hextets& ipv6) {
    ipv6_hextets hextets = ipv6;
    for (auto& hextet : hextets) {
        hextet = be16toh(hextet);
    }
    return hextets;
}

ipv6_hextets ipv6_to_be(const uint16_t* ipv6) {
    ipv6_hextets hextets = {};
    for (int i = 0; i < 8; i++) {
        hextets[i] = htobe16(ipv6[i]);
    }
    return hextets;
}

ipv6_hextets ipv6_to_le(const uint16_t* ipv6) {
    ipv6_hextets hextets = {};
    for (int i = 0; i < 8; i++) {
        hextets[i] = be16toh(ipv6[i]);
    }
    return hextets;
}

ipv6_bytes ipv6_to_be_bytes(const uint16_t* ipv6) {
    auto hextets_be = ipv6_to_be(ipv6);
    ipv6_bytes bytes = {};
    memcpy(bytes.data(), hextets_be.data(), bytes.size());
    return bytes;
}

ipv6_bytes ipv6_to_le_bytes(const uint16_t* ipv6) {
    auto hextets = ipv6_to_le(ipv6);
    ipv6_bytes bytes = {};
    memcpy(bytes.data(), hextets.data(), bytes.size());
    return bytes;
}
