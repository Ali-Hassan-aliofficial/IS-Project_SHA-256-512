#include <string>
#include <cstdint>
#include <vector>
#include <sstream>
#include <iomanip>
#include <cstring>

class SHA256 {
private:
    typedef uint32_t uint32;

    // Constants
    const uint32 hPrime[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };

    const uint32 k[64] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };

    uint32 h[8];                // Current hash value
    std::vector<uint8_t> buffer; // Buffer to hold data
    size_t totalBitsProcessed;  // Total number of bits processed

    void processBlock(const uint8_t* block);
    void finalize(std::vector<uint8_t>& paddedData);

    // Bitwise operations
    inline uint32 rotateRight(uint32 x, uint32 n) { return (x >> n) | (x << (32 - n)); }
    inline uint32 ch(uint32 x, uint32 y, uint32 z) { return (x & y) ^ (~x & z); }
    inline uint32 maj(uint32 x, uint32 y, uint32 z) { return (x & y) ^ (x & z) ^ (y & z); }
    inline uint32 sigma0(uint32 x) { return rotateRight(x, 2) ^ rotateRight(x, 13) ^ rotateRight(x, 22); }
    inline uint32 sigma1(uint32 x) { return rotateRight(x, 6) ^ rotateRight(x, 11) ^ rotateRight(x, 25); }
    inline uint32 gamma0(uint32 x) { return rotateRight(x, 7) ^ rotateRight(x, 18) ^ (x >> 3); }
    inline uint32 gamma1(uint32 x) { return rotateRight(x, 17) ^ rotateRight(x, 19) ^ (x >> 10); }

public:
    SHA256();
    void update(const std::string& data);
    std::string hash();
};





SHA256::SHA256() : buffer(), totalBitsProcessed(0) {
    std::copy(std::begin(hPrime), std::end(hPrime), h);
}

void SHA256::update(const std::string& data) {
    const uint8_t* input = reinterpret_cast<const uint8_t*>(data.c_str());
    size_t len = data.size();
    size_t offset = 0;

    // Append data to buffer and process in 512-bit chunks
    while (len > 0) {
        size_t space = 64 - buffer.size();
        size_t toCopy = std::min(len, space);
        buffer.insert(buffer.end(), input + offset, input + offset + toCopy);
        offset += toCopy;
        len -= toCopy;

        if (buffer.size() == 64) {
            processBlock(buffer.data());
            buffer.clear();
        }
    }

    totalBitsProcessed += data.size() * 8;
}

void SHA256::processBlock(const uint8_t* block) {
    uint32 w[64] = {0};

    // Prepare the message schedule
    for (size_t i = 0; i < 16; ++i) {
        w[i] = (block[i * 4] << 24) | (block[i * 4 + 1] << 16) | (block[i * 4 + 2] << 8) | block[i * 4 + 3];
    }
    for (size_t i = 16; i < 64; ++i) {
        w[i] = gamma1(w[i - 2]) + w[i - 7] + gamma0(w[i - 15]) + w[i - 16];
    }

    // Compression
    uint32 a = h[0], b = h[1], c = h[2], d = h[3];
    uint32 e = h[4], f = h[5], g = h[6], h_val = h[7];

    for (size_t i = 0; i < 64; ++i) {
        uint32 temp1 = h_val + sigma1(e) + ch(e, f, g) + k[i] + w[i];
        uint32 temp2 = sigma0(a) + maj(a, b, c);
        h_val = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }

    h[0] += a; h[1] += b; h[2] += c; h[3] += d;
    h[4] += e; h[5] += f; h[6] += g; h[7] += h_val;
}

void SHA256::finalize(std::vector<uint8_t>& paddedData) {
    uint64_t totalBits = totalBitsProcessed;

    // Add padding
    paddedData.push_back(0x80);
    while ((paddedData.size() % 64) != 56) {
        paddedData.push_back(0x00);
    }

    // Append length in bits
    for (int i = 7; i >= 0; --i) {
        paddedData.push_back((totalBits >> (i * 8)) & 0xFF);
    }
}

std::string SHA256::hash() {
    std::vector<uint8_t> paddedData(buffer);
    finalize(paddedData);

    for (size_t i = 0; i < paddedData.size(); i += 64) {
        processBlock(&paddedData[i]);
    }

    std::ostringstream result;
    for (uint32 x : h) {
        result << std::hex << std::setw(8) << std::setfill('0') << x;
    }

    return result.str();
}


#include <emscripten/emscripten.h>

extern "C" {
    EMSCRIPTEN_KEEPALIVE
    const char* compute_sha256(const char* input) {
        static std::string hash_output;

        // Validate input
        if (input == nullptr || std::string(input).empty()) {
            hash_output = "Error: Empty input provided.";
            return hash_output.c_str();
        }

        SHA256 sha256;

        // Input
        sha256.update(input);

        // SHA256 hashing

        hash_output = sha256.hash();  // Compute the SHA256 hash

        // Return the result
        return hash_output.c_str();
    }
}



// #include <iostream>


// int main() {
//     SHA256 sha256;

//     std::string input;
//     std::cout << "Enter string to hash: ";
//     std::getline(std::cin, input);

//     sha256.update(input);
//     std::cout << "SHA256: " << sha256.hash() << std::endl;

//     return 0;
// }






