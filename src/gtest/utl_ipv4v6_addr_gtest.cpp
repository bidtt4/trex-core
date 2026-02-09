#include <array>
#include <common/gtest.h>
#include <cstdint>
#include <cstring>

#include "utl_ipv4v6_addr.h"

TEST(ipv4v6_addr_test, ipv4_from_str) {
    auto addr = ipv4v6_addr::from_str("127.0.0.1");
    EXPECT_EQ((int)addr.version, (int)ipv4v6_addr::Version::V4);
    EXPECT_EQ(addr.addr.v4, 0x7f000001u);
}

TEST(ipv4v6_addr_test, ipv6_from_str) {
    auto addr = ipv4v6_addr::from_str("fe80::a002");
    EXPECT_EQ((int)addr.version, (int)ipv4v6_addr::Version::V6);
    EXPECT_EQ(addr.addr.v6[0], 0xfe80);
    EXPECT_EQ(addr.addr.v6[7], 0xa002);
}

TEST(ipv4v6_addr_test, ipv4_to_str) {
    auto addr = ipv4v6_addr::from_str("127.0.0.1");
    EXPECT_STREQ(addr.to_str().c_str(), "127.0.0.1");
}

TEST(ipv4v6_addr_test, ipv6_to_str) {
    auto addr = ipv4v6_addr::from_str("fe80::2");
    EXPECT_STREQ(addr.to_str().c_str(), "fe80::2");
}

TEST(ipv4v6_addr_test, ipv4_to_hex_str) {
    auto addr = ipv4v6_addr::from_str("127.0.0.1");
    EXPECT_STREQ(addr.to_hex_str().c_str(), "7f000001");
}

TEST(ipv4v6_addr_test, ipv6_to_hex_str) {
    auto addr = ipv4v6_addr::from_str("fe80::2");
    EXPECT_STREQ(addr.to_hex_str().c_str(), "fe800000000000000000000000000002");
}

TEST(ipv4v6_addr_test, ipv4_simple_addition) {
    auto addr = ipv4v6_addr::from_str("127.0.0.1");
    addr += 1;
    EXPECT_STREQ(addr.to_str().c_str(), "127.0.0.2");
}

TEST(ipv4v6_addr_test, ipv4_addition_with_octet_overflow) {
    auto addr = ipv4v6_addr::from_str("127.0.0.255");
    addr += 3;
    EXPECT_STREQ(addr.to_str().c_str(), "127.0.1.2");
}

TEST(ipv4v6_addr_test, ipv4_addition_with_ip_overflow) {
    auto addr = ipv4v6_addr::from_str("255.255.255.255");
    addr += 2;
    EXPECT_STREQ(addr.to_str().c_str(), "0.0.0.1");
}

TEST(ipv4v6_addr_test, ipv6_simple_addition) {
    auto addr = ipv4v6_addr::from_str("fe80::1");
    addr += 1;
    EXPECT_STREQ(addr.to_str().c_str(), "fe80::2");
}

TEST(ipv4v6_addr_test, ipv6_addition_with_hextet_overflow) {
    auto addr = ipv4v6_addr::from_str("fe80::ffff");
    addr += 3;
    EXPECT_STREQ(addr.to_str().c_str(), "fe80::1:2");
}

TEST(ipv4v6_addr_test, ipv6_addition_with_ip_overflow) {
    auto addr = ipv4v6_addr::from_str("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff");
    addr += 2;
    EXPECT_STREQ(addr.to_str().c_str(), "::1");
}

TEST(ipv4v6_addr_test, ipv4_simple_subtraction) {
    auto addr = ipv4v6_addr::from_str("127.0.0.1");
    addr -= 1;
    EXPECT_STREQ(addr.to_str().c_str(), "127.0.0.0");
}

TEST(ipv4v6_addr_test, ipv4_subtraction_with_octet_overflow) {
    auto addr = ipv4v6_addr::from_str("127.0.1.2");
    addr -= 3;
    EXPECT_STREQ(addr.to_str().c_str(), "127.0.0.255");
}

TEST(ipv4v6_addr_test, ipv4_subtraction_with_ip_overflow) {
    auto addr = ipv4v6_addr::from_str("0.0.0.1");
    addr -= 2;
    EXPECT_STREQ(addr.to_str().c_str(), "255.255.255.255");
}

TEST(ipv4v6_addr_test, ipv6_simple_subtraction) {
    auto addr = ipv4v6_addr::from_str("fe80::1");
    addr += 1;
    EXPECT_STREQ(addr.to_str().c_str(), "fe80::2");
}

TEST(ipv4v6_addr_test, ipv6_subtraction_with_hextet_overflow) {
    auto addr = ipv4v6_addr::from_str("fe80::1:2");
    addr -= 3;
    EXPECT_STREQ(addr.to_str().c_str(), "fe80::ffff");
}

TEST(ipv4v6_addr_test, ipv6_subtraction_with_ip_overflow) {
    auto addr = ipv4v6_addr::from_str("::1");
    addr -= 2;
    EXPECT_STREQ(addr.to_str().c_str(), "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff");
}

TEST(ipv4v6_addr_test, ipv4_distance_zero) {
    auto addr = ipv4v6_addr::from_str("127.0.0.1");
    EXPECT_EQ(ipv4v6_addr::distance(addr, addr), 0);
}

TEST(ipv4v6_addr_test, ipv4_distance_simple) {
    auto start = ipv4v6_addr::from_str("127.0.0.1");
    auto end = ipv4v6_addr::from_str("127.0.0.5");
    EXPECT_EQ(ipv4v6_addr::distance(start, end), 4);
}

TEST(ipv4v6_addr_test, ipv4_distance_reversed_arg_order) {
    auto start = ipv4v6_addr::from_str("127.0.0.1");
    auto end = ipv4v6_addr::from_str("127.0.0.5");
    EXPECT_EQ(ipv4v6_addr::distance(end, start), 4);
}

TEST(ipv4v6_addr_test, ipv4_distance_across_octet) {
    auto start = ipv4v6_addr::from_str("127.0.0.254");
    auto end = ipv4v6_addr::from_str("127.0.1.2");
    EXPECT_EQ(ipv4v6_addr::distance(start, end), 4);
}

TEST(ipv4v6_addr_test, ipv6_distance_zero) {
    auto addr = ipv4v6_addr::from_str("fe80::1");
    EXPECT_EQ(ipv4v6_addr::distance(addr, addr), 0);
}

TEST(ipv4v6_addr_test, ipv6_distance_simple) {
    auto start = ipv4v6_addr::from_str("fe80::1");
    auto end = ipv4v6_addr::from_str("fe80::5");
    EXPECT_EQ(ipv4v6_addr::distance(start, end), 4);
}

TEST(ipv4v6_addr_test, ipv6_distance_reversed_arg_order) {
    auto start = ipv4v6_addr::from_str("fe80::1");
    auto end = ipv4v6_addr::from_str("fe80::5");
    EXPECT_EQ(ipv4v6_addr::distance(end, start), 4);
}

TEST(ipv4v6_addr_test, ipv6_distance_across_octet) {
    auto start = ipv4v6_addr::from_str("fe80::fffe");
    auto end = ipv4v6_addr::from_str("fe80::1:2");
    EXPECT_EQ(ipv4v6_addr::distance(start, end), 4);
}

TEST(ipv4v6_addr_test, ipv6_distance_uint32_overflow) {
    auto start = ipv4v6_addr::from_str("fe80::fffe");
    auto end = ipv4v6_addr::from_str("fe70::1:2");
    EXPECT_EQ(ipv4v6_addr::distance(start, end), UINT32_MAX);
}

TEST(ipv4v6_addr_test, ipv4_operator_equal) {
    auto left = ipv4v6_addr::from_str("127.0.0.1");
    auto right = ipv4v6_addr::from_str("127.0.0.1");
    EXPECT_TRUE(left == right);
}

TEST(ipv4v6_addr_test, ipv4_operator_not_equal) {
    auto left = ipv4v6_addr::from_str("127.0.0.1");
    auto right = ipv4v6_addr::from_str("127.0.0.2");
    EXPECT_TRUE(left != right);
}

TEST(ipv4v6_addr_test, ipv4_operator_less) {
    auto left = ipv4v6_addr::from_str("fe80::fffe");
    auto right = ipv4v6_addr::from_str("fe80::1:2");
    EXPECT_TRUE(left < right);
}

TEST(ipv4v6_addr_test, ipv4_operator_greater) {
    auto left = ipv4v6_addr::from_str("fe80::1:2");
    auto right = ipv4v6_addr::from_str("fe80::fffe");
    EXPECT_TRUE(left > right);
}

TEST(ipv4v6_addr_test, ipv4_operator_less_equal) {
    auto left = ipv4v6_addr::from_str("127.0.0.1");
    auto right = ipv4v6_addr::from_str("127.0.0.1");
    EXPECT_TRUE(left <= right);
}

TEST(ipv4v6_addr_test, ipv4_operator_greater_equal) {
    auto left = ipv4v6_addr::from_str("127.0.0.1");
    auto right = ipv4v6_addr::from_str("127.0.0.1");
    EXPECT_TRUE(left >= right);
}

TEST(ipv4v6_addr_test, ipv6_operator_equal) {
    auto left = ipv4v6_addr::from_str("fe80::1");
    auto right = ipv4v6_addr::from_str("fe80::1");
    EXPECT_TRUE(left == right);
}

TEST(ipv4v6_addr_test, ipv6_operator_not_equal) {
    auto left = ipv4v6_addr::from_str("fe80::1");
    auto right = ipv4v6_addr::from_str("fe80::2");
    EXPECT_TRUE(left != right);
}

TEST(ipv4v6_addr_test, ipv6_operator_less) {
    auto left = ipv4v6_addr::from_str("fe80::fffe");
    auto right = ipv4v6_addr::from_str("fe80::1:2");
    EXPECT_TRUE(left < right);
}

TEST(ipv4v6_addr_test, ipv6_operator_greater) {
    auto left = ipv4v6_addr::from_str("fe80::1:2");
    auto right = ipv4v6_addr::from_str("fe80::fffe");
    EXPECT_TRUE(left > right);
}

TEST(ipv4v6_addr_test, ipv6_operator_less_equal) {
    auto left = ipv4v6_addr::from_str("fe80::1");
    auto right = ipv4v6_addr::from_str("fe80::1");
    EXPECT_TRUE(left <= right);
}

TEST(ipv4v6_addr_test, ipv6_operator_greater_equal) {
    auto left = ipv4v6_addr::from_str("fe80::1");
    auto right = ipv4v6_addr::from_str("fe80::1");
    EXPECT_TRUE(left >= right);
}

TEST(ipv4v6_addr_test, ipv4_range_size_same_value) {
    auto addr = ipv4v6_addr::from_str("127.0.0.1");
    EXPECT_EQ(ipv4v6_addr::range_size(addr, addr), 1);
}

TEST(ipv4v6_addr_test, ipv4_range_size_simple) {
    auto start = ipv4v6_addr::from_str("127.0.0.1");
    auto end = ipv4v6_addr::from_str("127.0.0.5");
    EXPECT_EQ(ipv4v6_addr::range_size(start, end), 5);
}

TEST(ipv4v6_addr_test, ipv4_range_size_reversed_arg) {
    auto start = ipv4v6_addr::from_str("127.0.0.1");
    auto end = ipv4v6_addr::from_str("127.0.0.5");
    EXPECT_EQ(ipv4v6_addr::range_size(end, start), 5);
}

TEST(ipv4v6_addr_test, ipv4_range_size_uint32_overflow) {
    auto start = ipv4v6_addr::from_str("0.0.0.0");
    auto end = ipv4v6_addr::from_str("255.255.255.255");
    EXPECT_EQ(ipv4v6_addr::range_size(start, end), UINT32_MAX);
}

TEST(ipv4v6_addr_test, ipv6_range_size_same_value) {
    auto addr = ipv4v6_addr::from_str("fe80::1");
    EXPECT_EQ(ipv4v6_addr::range_size(addr, addr), 1);
}

TEST(ipv4v6_addr_test, ipv6_range_size_simple) {
    auto start = ipv4v6_addr::from_str("fe80::1");
    auto end = ipv4v6_addr::from_str("fe80::5");
    EXPECT_EQ(ipv4v6_addr::range_size(start, end), 5);
}

TEST(ipv4v6_addr_test, ipv6_range_size_reversed_arg) {
    auto start = ipv4v6_addr::from_str("fe80::1");
    auto end = ipv4v6_addr::from_str("fe80::5");
    EXPECT_EQ(ipv4v6_addr::range_size(end, start), 5);
}

TEST(ipv4v6_addr_test, ipv6_range_size_uint32_overflow) {
    auto start = ipv4v6_addr::from_str("fe80::1");
    auto end = ipv4v6_addr::from_str("fe70::5");
    EXPECT_EQ(ipv4v6_addr::range_size(start, end), UINT32_MAX);
}

TEST(ipv4v6_addr_test, ipv4_ser_from_str) {
    auto expected = ipv4v6_addr::from_str("127.0.0.1");
    ipv4v6_addr addr;
    bool ret = addr.set_from_str("127.0.0.1");
    EXPECT_TRUE(ret);
    EXPECT_EQ((int)addr.version, (int)ipv4v6_addr::Version::V4);
    EXPECT_STREQ(addr.to_str().c_str(), expected.to_str().c_str());
}

TEST(ipv4v6_addr_test, ipv6_ser_from_str) {
    auto expected = ipv4v6_addr::from_str("fe80::1");
    ipv4v6_addr addr;
    bool ret = addr.set_from_str("fe80::1");
    EXPECT_TRUE(ret);
    EXPECT_EQ((int)addr.version, (int)ipv4v6_addr::Version::V6);
    EXPECT_STREQ(addr.to_str().c_str(), expected.to_str().c_str());
}

TEST(ipv4v6_addr_test, ipv4_factory_method_be) {
    uint32_t nw_order = 0x0100007fu;
    uint32_t expected = 0x7f000001u;
    auto addr = ipv4v6_addr::ipv4_be(nw_order);
    EXPECT_EQ((int)addr.version, (int)ipv4v6_addr::Version::V4);
    EXPECT_EQ(addr.addr.v4, expected);
    EXPECT_STREQ(addr.to_str().c_str(), "127.0.0.1");
}

TEST(ipv4v6_addr_test, ipv4_factory_method_le) {
    uint32_t expected = 0x7f000001u;
    auto addr = ipv4v6_addr::ipv4_le(expected);
    EXPECT_EQ((int)addr.version, (int)ipv4v6_addr::Version::V4);
    EXPECT_EQ(addr.addr.v4, expected);
    EXPECT_STREQ(addr.to_str().c_str(), "127.0.0.1");
}

TEST(ipv4v6_addr_test, ipv6_be_factory_method) {
    std::array<uint16_t, 8> expected_be{{0x80fe, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0200}};
    std::array<uint16_t, 8> expected_le{{0xfe80, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0002}};
    auto addr = ipv4v6_addr::ipv6_be(expected_be.data());
    EXPECT_EQ((int)addr.version, (int)ipv4v6_addr::Version::V6);
    EXPECT_EQ(memcmp(addr.addr.v6.data(), expected_le.data(), expected_le.size()), 0);
    EXPECT_STREQ(addr.to_str().c_str(), "fe80::2");
}

TEST(ipv4v6_addr_test, ipv4_is_less_than_ipv6) {
    auto v4 = ipv4v6_addr::from_str("127.0.0.1");
    auto v6 = ipv4v6_addr::from_str("fe80::1:2");
    EXPECT_TRUE(v4 < v6);
}

TEST(ipv4v6_addr_test, ipv4_is_not_equal_to_ipv6) {
    auto v4 = ipv4v6_addr::from_str("0.0.0.1");
    auto v6 = ipv4v6_addr::from_str("::1");
    EXPECT_TRUE(v4 != v6);
}

TEST(ipv4v6_addr_test, ipv6_from_ipv4_notation) {
    auto a1 = ipv4v6_addr::from_str("::48.0.109.182");
    auto a2 = ipv4v6_addr::from_str("::48.0.146.71");
    EXPECT_EQ((int)a1.version, (int)ipv4v6_addr::Version::V6);
    EXPECT_EQ(ipv4v6_addr::distance(a1, a2), 9361);
    EXPECT_EQ(ipv4v6_addr::range_size(a1, a2), 9362);
    EXPECT_TRUE(a1 < a2);
}

TEST(ipv4v6_addr_test, ipv6_compatible_from_ipv4) {
    auto v4_addr = ipv4v6_addr::from_str("48.0.109.182");
    auto v6_addr = ipv4v6_addr::ipv6_compatible(v4_addr);
    EXPECT_EQ((int)v6_addr.version, (int)ipv4v6_addr::Version::V6);
    EXPECT_STREQ(v6_addr.to_str().c_str(), "::48.0.109.182");
}

TEST(ipv4v6_addr_test, ipv6_compatible_from_ipv6) {
    auto v6_addr = ipv4v6_addr::from_str("2001::3000:6db6");
    auto same_addr = ipv4v6_addr::ipv6_compatible(v6_addr);
    EXPECT_EQ((int)same_addr.version, (int)ipv4v6_addr::Version::V6);
    EXPECT_STREQ(same_addr.to_str().c_str(), "2001::3000:6db6");
}
