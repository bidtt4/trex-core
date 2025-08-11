#pragma once

#include <cstdint>
#include <limits>
#include <random>

uint64_t entropy64() {
    std::random_device src;
    return (uint64_t(src()) << 32) | src();
}

struct XorShift32Star final {
    explicit XorShift32Star(uint64_t seed) : state(seed | 1) {} // state must be non-zero
    explicit XorShift32Star() : XorShift32Star(entropy64()) {}

    using result_type = uint32_t;

    static constexpr result_type min() { return std::numeric_limits<result_type>::min(); }
    static constexpr result_type max() { return std::numeric_limits<result_type>::max(); }
    
    result_type operator()() {
        state ^= state >> 11;
        state ^= state << 31;
        state ^= state >> 18;
        return (state * 0xd989bcacc137dcd5ULL) >> 32;
    }
    
    private:
    uint64_t state;
};
