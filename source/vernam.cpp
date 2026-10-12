#include <stdio.h>
#include <math.h>
#include <cstdint>
#include <random>
#include <iostream>
#include <vector>
#include <my_crypto_lib.hpp>
#include <iostream>
#include <fstream>
#include <cstdint>
#include <cstring>


void stream_file_vernam(const std::string& infile, const std::string& outfile, 
                     uint64_t K) {

    std::ifstream in(infile, std::ios::binary);
    std::ofstream out(outfile, std::ios::binary);

    if (!in.is_open() || !out.is_open()) {
        std::cerr << "Error open file!\n";
        return;
    }

    uint32_t chunk = 0;
    size_t chunk_index = 0;
    size_t total_bytes = 0;
    size_t errors_count = 0;

    while (in.read(reinterpret_cast<char*>(&chunk), sizeof(chunk))) {
        uint64_t m = chunk ^ K;

        //uint64_t processed_m = ;

        uint64_t out_chunk = K ^ m;

        if (chunk != out_chunk) {
            if (errors_count < 10) {
                std::cerr << "Mismatch at chunk " << chunk_index 
                          << " (byte " << chunk_index * 4 << "): "
                          << "IN=0x" << std::hex << chunk 
                          << " OUT=0x" << out_chunk << std::dec << "\n";
            }
            errors_count++;
        }

        out.write(reinterpret_cast<const char*>(&out_chunk), sizeof(out_chunk));

        chunk = 0;
        chunk_index++;
        total_bytes += sizeof(chunk);
    }

    std::streamsize bytesRead = in.gcount();
    if (bytesRead > 0) {
        uint32_t clean_chunk = 0;
        std::memcpy(&clean_chunk, &chunk, bytesRead);

        uint64_t m = chunk ^ K;

        uint64_t out_chunk = K ^ m;

        uint32_t mask = (bytesRead == 4) ? 0xFFFFFFFF : ((1U << (bytesRead * 8)) - 1);
        if ((clean_chunk & mask) != (out_chunk & mask)) {
            std::cerr << "Mismatch at TAIL (bytes: " << bytesRead << "): "
                      << "IN=0x" << std::hex << (clean_chunk & mask)
                      << " OUT=0x" << (out_chunk & mask) << std::dec << "\n";
            errors_count++;
        }

        out.write(reinterpret_cast<const char*>(&out_chunk), bytesRead);
        total_bytes += bytesRead;
    }

    in.close();
    out.close();

    std::cout << "\n=== STREAM FILE LOGS ===\n";
    std::cout << "Total chunks processed: " << chunk_index << "\n";
    std::cout << "Tail bytes read: " << bytesRead << "\n";
    std::cout << "Total bytes written: " << total_bytes << "\n";
    std::cout << "Total chunk mismatches: " << errors_count << "\n";
    std::cout << "========================\n\n";
}

uint64_t generate_xor_key(int file_size) {
    while (true) {
        uint64_t p = getRandom64(4294967300ULL, 8000000000ULL);
        if (p % 2 == 0) p++;

        if (millerRabinTest(p, 20)) {
            uint64_t q = (p - 1) / 2;
            
            // Проверяем q = (p - 1) / 2 на простоту
            if (millerRabinTest(q, 20)) {
                if (out_q != nullptr) {
                    *out_q = q;
                }
                return p;
            }
        }
    }
}


void vernam(std::string& in, std::string& out) {
    //uint64_t K = 0;

    int file_size = (in);

    std::vector<uint64_t> key(file_size); 





    std::cout << "Genearate Key\n";
    K = generate_xor_key(file_size);
    //std::cout << "Key (K) = " << K << "\n\n";

    stream_file_vernam(in, out, K);
}