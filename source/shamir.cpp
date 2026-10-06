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

/*1. функция для генерации простого рандомного p 
           mod_val = (p - 1);
2. Подбираем С:
    gcd(C, (p-1)) == 1

3. Находим D через расширенный алгоритм Евклида
    D = C^-1 mod(p - 1)
В итоге получили C и D для Алисы и Боба такие что: D * C mod(p - 1) = 1 

4. Шифрование сообщения m:
    Условие: m < p

    1) A: x1 = m^C mod p
    2) B: x2 = x1^C mod p 
*/


void stream_file(const std::string& infile, const std::string& outfile, 
                 uint64_t p, uint64_t Ca, uint64_t Da, uint64_t Cb, uint64_t Db) {

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

    // Читаем строго по 4 байта
    while (in.read(reinterpret_cast<char*>(&chunk), sizeof(chunk))) {
        uint64_t m = chunk;

        // Полный проход 4 шагов Шамира
        uint64_t processed_m = shamir(m, p, Ca, Da, Cb, Db);

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

        chunk = 0; // Сбрасываем буфер
        chunk_index++;
        total_bytes += sizeof(chunk);
    }

    // Обработка ХВОСТА файла (последние 1, 2 или 3 байта)
    std::streamsize bytesRead = in.gcount();
    if (bytesRead > 0) {
        // Так как цикл while завершился с ошибкой чтения (EOF),
        // в chunk уже находятся частично прочитанные байты.
        // Зануляем только старшие НЕпрочитанные байты для чистоты:
        uint32_t clean_chunk = 0;
        std::memcpy(&clean_chunk, &chunk, bytesRead);

        uint64_t m = clean_chunk;
        uint64_t processed_m = shamir(m, p, Ca, Da, Cb, Db);
        uint32_t out_chunk = static_cast<uint32_t>(processed_m);

        // Сравниваем только маску реально прочитанных байт
        uint32_t mask = (bytesRead == 4) ? 0xFFFFFFFF : ((1U << (bytesRead * 8)) - 1);
        if ((clean_chunk & mask) != (out_chunk & mask)) {
            std::cerr << "Mismatch at TAIL (bytes: " << bytesRead << "): "
                      << "IN=0x" << std::hex << (clean_chunk & mask)
                      << " OUT=0x" << (out_chunk & mask) << std::dec << "\n";
            errors_count++;
        }

        // Записываем ровно столько байт, сколько было прочитано
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

// void stream_file(const std::string& infile, const std::string& outfile, 
//                         uint64_t p, uint64_t Ca, uint64_t Da, uint64_t Cb, uint64_t Db) {

//     std::ifstream in(infile, std::ios::binary);
//     std::ofstream out(outfile, std::ios::binary);

//     if (!in.is_open() || !out.is_open()) {
//         std::cerr << "Error open file!\n";
//         return;
//     }

//     uint8_t byte_in = 0;
//     size_t byte_index = 0;
//     size_t errors_count = 0;

//     while (in.read(reinterpret_cast<char*>(&byte_in), 1)) {
//         uint64_t m = byte_in;

//         // Прогоняем через Шамира
//         uint64_t processed_m = shamir(m, p, Ca, Da, Cb, Db);
//         uint8_t byte_out = static_cast<uint8_t>(processed_m);

//         // ПРОВЕРКА: совпадает ли входящий байт с исходящим?
//         if (byte_in != byte_out) {
//             if (errors_count < 10) { // Выведем только первые 10 ошибок
//                 std::cerr << "Mismatch at byte " << byte_index 
//                           << ": IN=" << (int)byte_in 
//                           << " (" << std::hex << (int)byte_in << ")"
//                           << " OUT=" << (int)byte_out 
//                           << " (" << (int)byte_out << std::dec << ")\n";
//             }
//             errors_count++;
//         }

//         out.write(reinterpret_cast<const char*>(&byte_out), 1);
//         byte_index++;
//     }

//     in.close();
//     out.close();

//     std::cout << "Total bytes processed: " << byte_index << "\n";
//     std::cout << "Total byte errors: " << errors_count << "\n";
// }

uint64_t generate_C(uint64_t p){
    //uint64_t C = 0;
    
    if (p <= 3) {
        std::cerr << "Error: p must be greater than 3!\n";
        return 0;
    }
    //uint64_t mod = p - 1;
    while (true)
    {   
        uint64_t C = getRandom64(2, p -2);
        uint64_t res_gcd = 0;
        gcd(C, p, &res_gcd);
        if (res_gcd == 1){
            return C;
        }
    }
}



uint64_t encrypt_alice_step(uint64_t m, uint64_t p, uint64_t Ca) {
    uint64_t x1 = 0;
    fast_pow_mod(m, Ca, p, &x1);
    return x1;
}

uint64_t shamir(uint64_t m, uint64_t p, uint64_t Ca, uint64_t Da, uint64_t Cb, uint64_t Db) {
    uint64_t x1, x2, x3, x4;
    if (m >= p) {
        std::cerr << "Error: has to be m < p!\n";
    }else {
        fast_pow_mod(m, Ca, p, &x1);
        fast_pow_mod(x1, Cb, p, &x2);
        fast_pow_mod(x2, Da, p, &x3);
        fast_pow_mod(x3, Db, p, &x4);
    }
    return x4;
}

void shamir_key(bool user_input, std::string& in, std::string& out) {
    uint64_t p = 0, Ca = 0, Cb = 0, Da = 0, Db = 0;

    if (user_input) {
        std::cout << "Enter args: p, Ca, Cb: ";
        std::vector<uint64_t> input(3);
        for (size_t i = 0; i < 3; i++) {
            std::cin >> input[i];
        }
        
        p = input[0];
        Ca = input[1];
        Da = advanced_euclid(Ca, p - 1);

        Cb= input[2];
        Db = advanced_euclid(Cb, p - 1);

        if (!check_users_args(p)) {
            std::cout << "Warning: Input p is not prime!\n";
        }

    } else {
        std::cout << "Genearate C_ & D_\n";

        p = generate_p(nullptr);

        

        //ключи Алисы
        Ca = generate_C(p - 1);
        Da = advanced_euclid(Ca, p - 1);

        // ^- Расширенный алгоритм Евклида 
        // дополнительно находит целые коэффициенты x и y для соотношения Безу:a*x + b*y = gcd(a, b)
        // Возвращает D = C^(-1) mod (p -1)

        //ключи Боба
        Cb = generate_C(p - 1);
        Db = advanced_euclid(Cb, p - 1);

        uint64_t check_a = prevention_overflow_mod(Ca, Da, p - 1);
        uint64_t check_b = prevention_overflow_mod(Cb, Db, p - 1);

        if (check_a != 1 || check_b != 1) {
            std::cerr << "CRITICAL: Extended Euclid calculated wrong D!\n";
        }

        std::cout << "C (Alice) = " << Ca << "\n";
        std::cout << "D (Alice) = " << Da << "\n";
        std::cout << "C (Bob) = " << Cb << "\n";
        std::cout << "D (Bob)   = " << Db << "\n\n";
    }

    stream_file(in, out, p, Ca, Da, Cb, Db);

}