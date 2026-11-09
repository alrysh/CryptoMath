#include <cstdint>
#include <cstring>
#include <fstream>
#include <iostream>
#include <filesystem>
#include <vector>
#include <my_crypto_lib.hpp>

void stream_file_vernam(const std::string &infile, const std::string &outfile,
                        const std::vector<uint8_t> &key) {
    std::ifstream in(infile, std::ios::binary);
    std::ofstream out(outfile, std::ios::binary);

    if (!in.is_open() || !out.is_open()) {
        std::cerr << "Error open file!\n";
        return;
    }

    uint8_t chunk = 0;
    size_t chunk_index = 0;
    size_t total_bytes = 0;
    size_t errors_count = 0;

    while (in.read(reinterpret_cast<char *>(&chunk), sizeof(chunk))) {
        uint8_t k = key[chunk_index % key.size()];
        
        uint8_t m = chunk ^ k;
        uint8_t out_chunk = k ^ m;

        if (chunk != out_chunk) {
            if (errors_count < 10) {
                std::cerr << "Mismatch at byte " << chunk_index << ": "
                          << "IN=0x" << std::hex << (int)chunk << " OUT=0x"
                          << (int)out_chunk << std::dec << "\n";
            }
            errors_count++;
        }

        out.write(reinterpret_cast<const char *>(&out_chunk), sizeof(out_chunk));

        chunk_index++;
        total_bytes += sizeof(chunk);
    }

    in.close();
    out.close();

    std::cout << "\n=== STREAM FILE LOGS ===\n";
    std::cout << "Total bytes processed: " << chunk_index << "\n";
    std::cout << "Total bytes written: " << total_bytes << "\n";
    std::cout << "Total mismatches: " << errors_count << "\n";
    std::cout << "========================\n\n";
}

uint64_t generate_dh_shared_key(uint64_t p, uint64_t g) {
    uint64_t a = getRandom64(2, p - 2);
    uint64_t A = 0;
    fast_pow_mod(g, a, p, &A);

    uint64_t b = getRandom64(2, p - 2);
    uint64_t B = 0;
    fast_pow_mod(g, b, p, &B);

    std::cout << "DH Exchange completed:\n";
    std::cout << "  Alice public key A = " << A << "\n";
    std::cout << "  Bob public key   B = " << B << "\n";

    uint64_t K = 0;
    fast_pow_mod(B, a, p, &K); 

    std::cout << "  Shared Secret K  = " << K << "\n\n";
    return K;
}

void vernam(std::string &in, std::string &out) {
    if (!std::filesystem::exists(in)) {
        std::cerr << "Error: input file does not exist!\n";
        return;
    }
    uintmax_t file_size = std::filesystem::file_size(in);
    if (file_size == 0) {
        std::cerr << "Error: file is empty!\n";
        return;
    }

    std::cout << "1. Generating DH Parameters (p and g)...\n";
    uint64_t q = 0;
    uint64_t p = generate_p(&q);
    uint64_t g = find_primitive_root(p);

    std::cout << "p = " << p << "\n";
    std::cout << "g = " << g << "\n\n";

    std::cout << "2. Executing Diffie-Hellman Key Exchange...\n";
    uint64_t K = generate_dh_shared_key(p, g);

    std::cout << "3. Expanding Key Stream to File Size (" << file_size << " bytes)...\n";
    std::vector<uint8_t> key(file_size);
    uint64_t state = K;
    
    for (size_t i = 0; i < file_size; i++) {
        state = state * 6364136223846793005ULL + 1442695040888963407ULL;
        key[i] = static_cast<uint8_t>(state >> 56);
    }

    std::cout << "Key stream generated successfully.\n\n";

    stream_file_vernam(in, out, key);
}