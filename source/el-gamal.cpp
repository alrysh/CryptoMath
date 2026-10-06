#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cstring>
#include <cstdint>
#include <my_crypto_lib.hpp>



// Генерация сеансового ключа k, взаимно простого с p - 1
uint64_t generate_k(uint64_t p) {
    uint64_t mod = p - 1;
    while (true) {   
        uint64_t k = getRandom64(2, p - 2);
        uint64_t res_gcd = 0;
        gcd(k, mod, &res_gcd);
        if (res_gcd == 1) {
            return k;
        }
    }
}

// Шифрование одного блока (ElGamal Encrypt)
ElGamalCiphertext elgamal_encrypt(uint64_t m, uint64_t p, uint64_t g, uint64_t y) {
    if (m >= p) {
        std::cerr << "Error: has to be m < p!\n";
    }
    
    uint64_t k = generate_k(p);
    
    uint64_t a = 0;
    fast_pow_mod(g, k, p, &a); // a = g^k mod p
    
    uint64_t y_k = 0;
    fast_pow_mod(y, k, p, &y_k); // y^k mod p
    
    uint64_t b = prevention_overflow_mod(m, y_k, p); // b = (m * y^k) mod p
    
    return {a, b};
}

// Расшифровка одного блока (ElGamal Decrypt)
uint64_t elgamal_decrypt(const ElGamalCiphertext& cipher, uint64_t p, uint64_t x) {
    // m = b * a^(p - 1 - x) mod p
    uint64_t exp = p - 1 - x;
    uint64_t a_pow = 0;
    fast_pow_mod(cipher.a, exp, p, &a_pow); // a^(p - 1 - x) mod p
    
    uint64_t m = prevention_overflow_mod(cipher.b, a_pow, p); // b * a_pow mod p
    return m;
}

// Полный полный проход (Encrypt -> Decrypt) для одного блока m
uint64_t elgamal_process_block(uint64_t m, uint64_t p, uint64_t g, uint64_t y, uint64_t x) {
    ElGamalCiphertext cipher = elgamal_encrypt(m, p, g, y);
    return elgamal_decrypt(cipher, p, x);
}

// Функция сквозной потоковой обработки файла по 4 байта
void stream_file_elgamal(const std::string& infile, const std::string& outfile, 
                         uint64_t p, uint64_t g, uint64_t y, uint64_t x) {

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
        uint64_t m = chunk;

        uint64_t processed_m = elgamal_process_block(m, p, g, y, x);

        uint32_t out_chunk = static_cast<uint32_t>(processed_m);

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

        uint64_t m = clean_chunk;
        uint64_t processed_m = elgamal_process_block(m, p, g, y, x);
        uint32_t out_chunk = static_cast<uint32_t>(processed_m);

        // Сравниваем только маску реально прочитанных байт
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

    std::cout << "\n=== STREAM FILE LOGS (ELGAMAL) ===\n";
    std::cout << "Total chunks processed: " << chunk_index << "\n";
    std::cout << "Tail bytes read: " << bytesRead << "\n";
    std::cout << "Total bytes written: " << total_bytes << "\n";
    std::cout << "Total chunk mismatches: " << errors_count << "\n";
    std::cout << "==================================\n\n";
}

void elgamal_key(bool user_input, std::string& in, std::string& out) {
    uint64_t p = 0, g = 0, x = 0, y = 0;

    if (user_input) {
        std::cout << "Enter args: p, g, x: ";
        std::vector<uint64_t> input(3);
        for (size_t i = 0; i < 3; i++) {
            std::cin >> input[i];
        }
        
        p = input[0];
        g = input[1];
        x = input[2];

        // Открытый ключ y = g^x mod p
        fast_pow_mod(g, x, p, &y);

        if (!check_users_args(p)) {
            std::cout << "Warning: Input p is not prime!\n";
        }

    } else {
        std::cout << "Generate p, g, x, y (ElGamal)\n";

        p = generate_p(nullptr); 
        
        uint64_t q = 0;
        p = generate_p(&q);
        g = generate_g(p, q);

        x = getRandom64(2, p - 2);

        // Открытый ключ y = g^x mod p
        fast_pow_mod(g, x, p, &y);

        std::cout << "p (Prime)          = " << p << "\n";
        std::cout << "g (Generator)      = " << g << "\n";
        std::cout << "x (Private Key)    = " << x << "\n";
        std::cout << "y (Public Key g^x) = " << y << "\n\n";
    }

    stream_file_elgamal(in, out, p, g, y, x);
}