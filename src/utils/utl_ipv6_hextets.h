#ifndef UTL_IPV6_HEXTETS_H
#define UTL_IPV6_HEXTETS_H

#include <array>
#include <cstdint>

using ipv6_hextets = std::array<std::uint16_t, 8>;
using ipv6_bytes = std::array<std::uint8_t, 16>;

constexpr ipv6_hextets IPV6_UNSPECIFIED = {};

ipv6_hextets ipv6_to_be(const ipv6_hextets& ipv6);
ipv6_hextets ipv6_to_le(const ipv6_hextets& ipv6);

ipv6_hextets ipv6_to_be(const uint16_t* ipv6);
ipv6_hextets ipv6_to_le(const uint16_t* ipv6);

ipv6_bytes ipv6_to_be_bytes(const uint16_t* ipv6);
ipv6_bytes ipv6_to_le_bytes(const uint16_t* ipv6);

#endif // UTL_IPV6_HEXTETS_H
