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

/* Подпись RSA
1. A:
Генерирует P, Q,  P != Q - простые 
Вычилсяет:  N = PQ
            f(N) = (P-1)(Q-1)

1.2.
    d : gcd((N), d) = 1
    с : cd(mod phi(N)) = 1 //

Находим _c_ через расширенный алгоритм Евклида
    c = d^-1 mod(p - 1)
В итоге получили c и d для Алисы и Боба такие что: c * d mod phi(n) = 1 

Открытые: N, d 
Закрытые: с

2. Алиса вычисляет значение хэш-функции документа  h = H(m), h < N
    s = h^c (mod N)

Документ: m и s

3. Боб получает m, s, N, d
    h = H(m)
e = s^d (mod N)

 e = h - подлинность доказана
*/

/* Шифр RSA

1. B:
Генерирует P, Q,  P != Q - простые
Вычилсяет:  N = PQ
            phi = (P-1)(Q-1)

1.2.
    d : gcd((N), d) = 1, d < phi

Находим _c_ через расширенный алгоритм Евклида
    c = d^-1 mod(p - 1)
В итоге получили c и d для Боба такие что: c * d mod phi = 1 

Открытые: N, d 
Закрытые: с

2.

A: e = m^d mod N

B: e^c = mod N

*/


void stream_file_rsa(const std::string& infile, const std::string& outfile, 
                     uint64_t Db, uint64_t Cb, uint64_t N) {

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
        uint64_t m = chunk; // m гарантированно меньше N

        // 1. Шифрование: e = m^Db mod N
        __int128_t e = 0;
        fast_pow_mod_128(m, Db, N, &e); 

        // 2. Расшифрование: processed_m = e^Cb mod N
        __int128_t processed_m = 0;
        fast_pow_mod_128(e, Cb, N, &processed_m); 

        // Исходный блок восстановлен
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
        // Читаем только bytesRead байт из того, что успело считаться
        std::memcpy(&clean_chunk, &chunk, bytesRead);

        uint64_t m = clean_chunk;

        __int128_t e = 0;
        fast_pow_mod_128(m, Db, N, &e);

        __int128_t processed_m = 0;
        fast_pow_mod_128(e, Cb, N, &processed_m);

        uint32_t out_chunk = static_cast<uint32_t>(processed_m);

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

__int128_t generate_pair_gcd_128(__int128_t phi) {
    if (phi <= 3) return 0;
    
    while (true) {
        uint64_t val = getRandom64(3, 65537);
        if (val % 2 == 0) val++;
        //uint64_t val = 65537;
        
        __int128_t res_gcd = 0;
        gcd_128(val, phi, &res_gcd);
        if (res_gcd == 1) {
            return val;
        }
    }
}

uint64_t generate_p_rsa(uint64_t *out_q) {
    while (true) {
        uint64_t p = getRandom64(65537, 2147483647);
        if (p % 2 == 0) p++;

        if (millerRabinTest(p, 20)) {
            uint64_t q = (p - 1) / 2;
            
            //Проверяем q = (p - 1) / 2 на простоту
            if (millerRabinTest(q, 20)) {
                if (out_q != nullptr) {
                    *out_q = q;
                }
                return p;
            }
        }
    }
}


void rsa(bool user_input, std::string& in, std::string& out) {
    uint64_t p = 0, q = 0, N = 0, Db = 0, Cb = 0; //, Da = 0
    //__int128_t f = 0;
    uint64_t f = 0;

    if (user_input) {
        std::cout << "Enter args: p, q, Db: ";
        std::vector<uint64_t> input(3);
        for (size_t i = 0; i < 3; i++) {
            std::cin >> input[i];
        }
        
        p = input[0];
        q = input[1];

        Db = input[2];

        N = p * q;
        //f = static_cast<__int128_t>(p - 1) * static_cast<__int128_t>(q - 1);
        f = (p - 1) * (q - 1);


        if (!check_users_args(p) || !check_users_args(q)) {
            std::cout << "Warning: Input p or q is not prime!\n";
        }

        Cb = advanced_euclid(Db, f);
        std::cout << "C (Bob)  = " << Cb << "\n\n";

    } else {
        std::cout << "Genearate P_ & Q_\n";

        p = generate_p_rsa(nullptr);
        q = generate_p_rsa(nullptr);

        N = p * q;
        f = (p - 1) * (q - 1);

        // d : gcd((N), d) = 1, d < phi
        Db = generate_pair_gcd_128(f);

        Cb = advanced_euclid(Db, f);

        // uint64_t check_b = prevention_overflow_mod(Cb, Db, p - 1);

        // if (check_a != 1) {
        //     std::cerr << "CRITICAL: Extended Euclid calculated wrong D!\n";
        // }

        std::cout << "p = " << p << "\n";
        std::cout << "q = " << q << "\n";
        std::cout << "D (Bob) = " << Db << "\n";
        std::cout << "C (Bob)  = " << Cb << "\n\n";
    }

    stream_file_rsa(in, out, Db, Cb, N);
    // в нем шифровка: e = prevention_overflow_mod(m, Db, N); m - сообщение 
    
}