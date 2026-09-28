// sha256.h
// ---------------------------------------------------------------------------
// A small, self-contained SHA-256 implementation using only the C++ standard
// library (<cstdint>, <cstring>, <string>, <sstream>, <iomanip>).
//
// This is adapted from the well-known public-domain SHA-256 reference
// algorithm (based on the description in FIPS PUB 180-4). It is written from
// scratch here so the project has NO third-party dependencies, which keeps
// it compiler/portable-friendly for a student/internship project.
//
// IMPORTANT SECURITY NOTE (read the README's Security Analysis section too):
// Plain SHA-256 is a fast, general-purpose cryptographic hash. It is
// perfectly fine for things like file-integrity checks, but it is NOT the
// recommended algorithm for password storage in a production system,
// because it is fast to compute, which makes brute-force / GPU attacks
// cheap. Production systems should use a slow, memory-hard, password-
// specific KDF such as bcrypt, scrypt, or Argon2.
//
// We use SHA-256 here (combined with a per-user random salt) because it is
// something we can implement with pure standard C++ with no external
// libraries, and it is dramatically better than storing plaintext
// passwords. This trade-off is explained in the README.
// ---------------------------------------------------------------------------
#ifndef SHA256_H
#define SHA256_H

#include <cstdint>
#include <cstring>
#include <string>
#include <sstream>
#include <iomanip>
#include <array>
#include <vector>

class SHA256 {
public:
    // Computes the SHA-256 digest of `input` and returns it as a
    // lowercase hexadecimal string (64 characters).
    static std::string hash(const std::string& input) {
        SHA256 ctx;
        ctx.update(reinterpret_cast<const uint8_t*>(input.data()), input.size());
        return ctx.finalize();
    }

private:
    // ---- internal state ----
    uint32_t state[8];
    uint64_t bitLength;
    std::vector<uint8_t> buffer;

    SHA256() {
        bitLength = 0;
        buffer.clear();
        // Initial hash values (first 32 bits of the fractional parts of the
        // square roots of the first 8 primes), as defined by the standard.
        state[0] = 0x6a09e667; state[1] = 0xbb67ae85;
        state[2] = 0x3c6ef372; state[3] = 0xa54ff53a;
        state[4] = 0x510e527f; state[5] = 0x9b05688c;
        state[6] = 0x1f83d9ab; state[7] = 0x5be0cd19;
    }

    static uint32_t rotr(uint32_t x, uint32_t n) { return (x >> n) | (x << (32 - n)); }

    void transform(const uint8_t* data) {
        static const uint32_t k[64] = {
            0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
            0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
            0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
            0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
            0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
            0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
            0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
            0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
        };

        uint32_t w[64];
        for (int i = 0; i < 16; ++i) {
            w[i] = (data[i * 4] << 24) | (data[i * 4 + 1] << 16) |
                   (data[i * 4 + 2] << 8) | (data[i * 4 + 3]);
        }
        for (int i = 16; i < 64; ++i) {
            uint32_t s0 = rotr(w[i-15], 7) ^ rotr(w[i-15], 18) ^ (w[i-15] >> 3);
            uint32_t s1 = rotr(w[i-2], 17) ^ rotr(w[i-2], 19) ^ (w[i-2] >> 10);
            w[i] = w[i-16] + s0 + w[i-7] + s1;
        }

        uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
        uint32_t e = state[4], f = state[5], g = state[6], h = state[7];

        for (int i = 0; i < 64; ++i) {
            uint32_t S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
            uint32_t ch = (e & f) ^ (~e & g);
            uint32_t temp1 = h + S1 + ch + k[i] + w[i];
            uint32_t S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
            uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t temp2 = S0 + maj;

            h = g; g = f; f = e; e = d + temp1;
            d = c; c = b; b = a; a = temp1 + temp2;
        }

        state[0] += a; state[1] += b; state[2] += c; state[3] += d;
        state[4] += e; state[5] += f; state[6] += g; state[7] += h;
    }

    void update(const uint8_t* data, size_t len) {
        bitLength += static_cast<uint64_t>(len) * 8;
        buffer.insert(buffer.end(), data, data + len);
        while (buffer.size() >= 64) {
            transform(buffer.data());
            buffer.erase(buffer.begin(), buffer.begin() + 64);
        }
    }

    std::string finalize() {
        // Padding: append 0x80, then zeros, then the 64-bit big-endian
        // original bit length, so the total length is a multiple of 64 bytes.
        uint64_t originalBitLength = bitLength;
        buffer.push_back(0x80);
        while (buffer.size() % 64 != 56) buffer.push_back(0x00);

        for (int i = 7; i >= 0; --i) {
            buffer.push_back(static_cast<uint8_t>((originalBitLength >> (i * 8)) & 0xff));
        }

        while (buffer.size() >= 64) {
            transform(buffer.data());
            buffer.erase(buffer.begin(), buffer.begin() + 64);
        }

        std::ostringstream oss;
        for (int i = 0; i < 8; ++i) {
            oss << std::hex << std::setw(8) << std::setfill('0') << state[i];
        }
        return oss.str();
    }
};

#endif // SHA256_H
