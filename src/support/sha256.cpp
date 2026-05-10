/**
 * @file sha256.cpp
 * @brief Implements a small in-tree SHA-256 helper used by archive analysis
 * and resource metadata tracking.
 */

#include "support/sha256.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace teampandory::powpack::detail {
namespace {

constexpr std::array<std::uint32_t, 64> roundConstants = {
    0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U, 0x3956c25bU, 0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U,
    0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U, 0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U,
    0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU, 0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
    0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U, 0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U,
    0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U, 0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
    0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U, 0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
    0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U, 0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
    0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U, 0x90befffAU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U,
};

constexpr std::array<std::uint32_t, 8> initialState = {
    0x6a09e667U,
    0xbb67ae85U,
    0x3c6ef372U,
    0xa54ff53aU,
    0x510e527fU,
    0x9b05688cU,
    0x1f83d9abU,
    0x5be0cd19U,
};

constexpr std::uint32_t rotateRight(std::uint32_t value, std::uint32_t bits) {
    return (value >> bits) | (value << (32U - bits));
}

constexpr std::uint32_t choose(std::uint32_t x, std::uint32_t y, std::uint32_t z) {
    return (x & y) ^ (~x & z);
}

constexpr std::uint32_t majority(std::uint32_t x, std::uint32_t y, std::uint32_t z) {
    return (x & y) ^ (x & z) ^ (y & z);
}

constexpr std::uint32_t bigSigma0(std::uint32_t x) {
    return rotateRight(x, 2) ^ rotateRight(x, 13) ^ rotateRight(x, 22);
}

constexpr std::uint32_t bigSigma1(std::uint32_t x) {
    return rotateRight(x, 6) ^ rotateRight(x, 11) ^ rotateRight(x, 25);
}

constexpr std::uint32_t smallSigma0(std::uint32_t x) {
    return rotateRight(x, 7) ^ rotateRight(x, 18) ^ (x >> 3);
}

constexpr std::uint32_t smallSigma1(std::uint32_t x) {
    return rotateRight(x, 17) ^ rotateRight(x, 19) ^ (x >> 10);
}

std::array<std::uint8_t, 32> sha256Digest(const std::vector<std::uint8_t> &data) {
    std::vector<std::uint8_t> padded = data;
    const std::uint64_t bitLength = static_cast<std::uint64_t>(data.size()) * 8U;

    padded.push_back(0x80U);
    while ((padded.size() % 64U) != 56U) {
        padded.push_back(0x00U);
    }
    for (int shift = 56; shift >= 0; shift -= 8) {
        padded.push_back(static_cast<std::uint8_t>((bitLength >> shift) & 0xffU));
    }

    auto state = initialState;
    std::array<std::uint32_t, 64> schedule {};

    for (std::size_t blockOffset = 0; blockOffset < padded.size(); blockOffset += 64U) {
        for (std::size_t word = 0; word < 16U; ++word) {
            const std::size_t offset = blockOffset + word * 4U;
            schedule[word] = (static_cast<std::uint32_t>(padded[offset]) << 24U) |
                             (static_cast<std::uint32_t>(padded[offset + 1]) << 16U) |
                             (static_cast<std::uint32_t>(padded[offset + 2]) << 8U) |
                             static_cast<std::uint32_t>(padded[offset + 3]);
        }
        for (std::size_t word = 16U; word < 64U; ++word) {
            schedule[word] = smallSigma1(schedule[word - 2]) + schedule[word - 7] +
                             smallSigma0(schedule[word - 15]) + schedule[word - 16];
        }

        std::uint32_t a = state[0];
        std::uint32_t b = state[1];
        std::uint32_t c = state[2];
        std::uint32_t d = state[3];
        std::uint32_t e = state[4];
        std::uint32_t f = state[5];
        std::uint32_t g = state[6];
        std::uint32_t h = state[7];

        for (std::size_t round = 0; round < 64U; ++round) {
            const std::uint32_t temp1 = h + bigSigma1(e) + choose(e, f, g) + roundConstants[round] + schedule[round];
            const std::uint32_t temp2 = bigSigma0(a) + majority(a, b, c);
            h = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }

        state[0] += a;
        state[1] += b;
        state[2] += c;
        state[3] += d;
        state[4] += e;
        state[5] += f;
        state[6] += g;
        state[7] += h;
    }

    std::array<std::uint8_t, 32> digest {};
    for (std::size_t index = 0; index < state.size(); ++index) {
        digest[index * 4] = static_cast<std::uint8_t>((state[index] >> 24U) & 0xffU);
        digest[index * 4 + 1] = static_cast<std::uint8_t>((state[index] >> 16U) & 0xffU);
        digest[index * 4 + 2] = static_cast<std::uint8_t>((state[index] >> 8U) & 0xffU);
        digest[index * 4 + 3] = static_cast<std::uint8_t>(state[index] & 0xffU);
    }
    return digest;
}

}  // namespace

std::string sha256Hex(const std::vector<std::uint8_t> &data) {
    const auto digest = sha256Digest(data);
    static constexpr char hex[] = "0123456789abcdef";

    std::string result;
    result.reserve(digest.size() * 2U);
    for (const auto byte : digest) {
        result.push_back(hex[(byte >> 4U) & 0x0fU]);
        result.push_back(hex[byte & 0x0fU]);
    }
    return result;
}

}  // namespace teampandory::powpack::detail
