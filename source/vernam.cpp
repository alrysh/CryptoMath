
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iostream>
#include <math.h>
#include <my_crypto_lib.hpp>
#include <random>
#include <stdio.h>
#include <vector>

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
    uint8_t m = chunk ^ key[chunk_index];

    uint8_t out_chunk = key[chunk_index] ^ m;

    if (chunk != out_chunk) {
      if (errors_count < 10) {
        std::cerr << "Mismatch at byte " << chunk_index << ": "
                  << "IN=0x" << std::hex << (int)chunk << " OUT=0x"
                  << (int)out_chunk << std::dec << "\n";
      }
      errors_count++;
    }

    out.write(reinterpret_cast<const char *>(&out_chunk), sizeof(out_chunk));

    chunk = 0;
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

uint64_t generate_xor_key(int file_size, uint64_t *out_q) {
  while (true) {
    uint64_t p = getRandom64(4294967300ULL, 8000000000ULL);
    if (p % 2 == 0)
      p++;

    if (millerRabinTest(p, 20)) {
      uint64_t q = (p - 1) / 2;

      if (millerRabinTest(q, 20)) {
        if (out_q != nullptr) {
          *out_q = q;
        }
        return p;
      }
    }
  }
}

void vernam(std::string &in, std::string &out) {
  std::ifstream file(in, std::ios::binary | std::ios::ate);
  if (!file.is_open()) {
    std::cerr << "Error: cannot open input file!\n";
    return;
  }
  int file_size = static_cast<int>(file.tellg());
  file.close();

  std::cout << "Genearate Key\n";

  uint64_t q = 0;
  uint64_t K = generate_xor_key(file_size, &q);

  std::vector<uint8_t> key(file_size);
  uint64_t state = K;
  for (int i = 0; i < file_size; i++) {
    state = state * 6364136223846793005ULL + 1442695040888963407ULL;
    key[i] = static_cast<uint8_t>(state >> 56);
  }

  std::cout << "Key stream size: " << key.size() << " bytes\n\n";

  stream_file_vernam(in, out, key);
}