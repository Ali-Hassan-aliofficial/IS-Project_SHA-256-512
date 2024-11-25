#include <string>
#include <cstdint>
#include <vector>
#include <cstring>
#include <iostream>
#include <sstream>
#include <iomanip>
using namespace std;

class SHA256 {
private:
    typedef uint32_t uint32;

    const uint32 hPrime[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };

    uint32 h[8];                // Current hash value
    vector<uint8_t> buffer;     // Buffer to hold data
    size_t totalBitsProcessed;  // Total number of bits processed

    void processBlock(const uint8_t* block); 

public:
    void finalize(vector<uint8_t>& paddedData);
    SHA256();
    void update(const string& data);
    string hash(); 
};

// Constructor
SHA256::SHA256() : buffer(), totalBitsProcessed(0) {
    copy(begin(hPrime), end(hPrime), h);
}

// Update function
void SHA256::update(const string& data) {
    const uint8_t* input = reinterpret_cast<const uint8_t*>(data.c_str());
    size_t len = data.size();
    size_t offset = 0;

    while (len > 0) {
        size_t space = 64 - buffer.size();
        size_t toCopy = min(len, space);
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

// Finalize function
void SHA256::finalize(vector<uint8_t>& paddedData) {
    uint64_t totalBits = totalBitsProcessed;

    paddedData.push_back(0x80); // Append a single 1 bit
    while ((paddedData.size() % 64) != 56) {
        paddedData.push_back(0x00);
    }

    for (int i = 7; i >= 0; --i) {
        paddedData.push_back((totalBits >> (i * 8)) & 0xFF);
    }
}

// Stub for processBlock
void SHA256::processBlock(const uint8_t* block) {
    cout << "processBlock called (stub)" << endl;
}

int main() {
    SHA256 sha256;

    string input;
    cout << "Enter string to hash: ";
    getline(cin, input);

    sha256.update(input);

    vector<uint8_t> paddedData;
    sha256.finalize(paddedData);

    return 0;
}
