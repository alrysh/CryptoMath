#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cstdint>
#include <cstring>
#include <iomanip>

#include <openssl/evp.h>
#include <my_crypto_lib.hpp>

uint64_t find_gost_a(uint64_t p, uint64_t q, uint64_t b) {
    for (uint64_t g = 2; g < p; ++g) {
        __int128_t a_128 = 0;
        fast_pow_mod_128(g, b, p, &a_128);
        if (a_128 > 1) {
            return static_cast<uint64_t>(a_128);
        }
    }
    return 0;
}

bool sign_file_gost(const std::string& doc_path, const std::string& sig_path,
                    uint64_t x, uint64_t p, uint64_t q, uint64_t a) {
    std::vector<uint8_t> hash = compute_file_hash_sha256(doc_path);
    if (hash.empty()) return false;

    std::cout << "[+] Calculated Hash: ";
    print_hex_digest(hash);

    std::ofstream sig_out(sig_path, std::ios::binary);
    if (!sig_out.is_open()) return false;

    for (uint8_t byte_val : hash) {
        uint64_t h = (byte_val == 0) ? 1 : byte_val;
        uint64_t r = 0;
        uint64_t s = 0;

        while (true) {
            uint64_t k = getRandom64(1, q - 1);

            __int128_t ak_mod_p = 0;
            fast_pow_mod_128(a, k, p, &ak_mod_p);
            r = static_cast<uint64_t>(ak_mod_p % q);
            if (r == 0) continue;

            __int128_t kh = static_cast<__int128_t>(k) * h;
            __int128_t xr = static_cast<__int128_t>(x) * r;
            s = static_cast<uint64_t>((kh + xr) % q);
            if (s != 0) break;
        }

        sig_out.write(reinterpret_cast<const char*>(&r), sizeof(r));
        sig_out.write(reinterpret_cast<const char*>(&s), sizeof(s));
    }

    sig_out.close();
    return true;
}

bool verify_file_gost(const std::string& doc_path, const std::string& sig_path,
                      uint64_t y, uint64_t p, uint64_t q, uint64_t a) {
    std::vector<uint8_t> current_hash = compute_file_hash_sha256(doc_path);
    if (current_hash.empty()) return false;

    std::ifstream sig_in(sig_path, std::ios::binary);
    if (!sig_in.is_open()) return false;

    std::cout << "[*] Current doc hash:    ";
    print_hex_digest(current_hash);

    for (size_t i = 0; i < current_hash.size(); ++i) {
        uint64_t r = 0;
        uint64_t s = 0;

        if (!sig_in.read(reinterpret_cast<char*>(&r), sizeof(r)) ||
            !sig_in.read(reinterpret_cast<char*>(&s), sizeof(s))) {
            sig_in.close();
            std::cout << "[FAIL] Signature file format corrupted!\n\n";
            return false;
        }

        if (r <= 0 || r >= q || s <= 0 || s >= q) {
            sig_in.close();
            std::cout << "[FAIL] Signature values out of range!\n\n";
            return false;
        }

        uint64_t h = (current_hash[i] == 0) ? 1 : current_hash[i];
        uint64_t h_inv = advanced_euclid(h, q);

        __int128_t u1 = (static_cast<__int128_t>(s) * h_inv) % q;
        __int128_t u2 = (-static_cast<__int128_t>(r) * static_cast<__int128_t>(h_inv)) % q;
        if (u2 < 0) {
            u2 += q;
        }

        __int128_t au1 = 0;
        __int128_t yu2 = 0;
        fast_pow_mod_128(a, static_cast<uint64_t>(u1), p, &au1);
        fast_pow_mod_128(y, static_cast<uint64_t>(u2), p, &yu2);

        __int128_t v = ((au1 * yu2) % p) % q;

        if (static_cast<uint64_t>(v) != r) {
            sig_in.close();
            std::cout << "[FAIL] Signature is INVALID for byte " << i << "!\n\n";
            return false;
        }
    }

    sig_in.close();
    std::cout << "[SUCCESS] Signature is VALID!\n\n";
    return true;
}

void gost_signature(bool user_input, const std::string& doc_file, const std::string& sig_file) {
    uint64_t p = 0, q = 0, a = 0, x = 0, y = 0;

    if (user_input) {
        std::cout << "Enter args (p, q, a, x): ";
        std::cin >> p >> q >> a >> x;

        __int128_t y_128 = 0;
        fast_pow_mod_128(a, x, p, &y_128);
        y = static_cast<uint64_t>(y_128);

        std::cout << "Calculated public key y = " << y << "\n\n";
    } else {
        while (true) {
            q = getRandom64(65537, 2147483647);
            if (q % 2 == 0) q++;
            if (!millerRabinTest(q, 20)) continue;

            uint64_t b = 2;
            bool found_p = false;
            while (b < 10000) {
                p = b * q + 1;
                if (millerRabinTest(p, 20)) {
                    a = find_gost_a(p, q, b);
                    if (a > 1) {
                        found_p = true;
                        break;
                    }
                }
                b += 2;
            }
            if (found_p) break;
        }

        x = getRandom64(1, q - 1);

        __int128_t y_128 = 0;
        fast_pow_mod_128(a, x, p, &y_128);
        y = static_cast<uint64_t>(y_128);

        std::cout << "p = " << p << "\n";
        std::cout << "q = " << q << "\n";
        std::cout << "a = " << a << "\n";
        std::cout << "Public key  (y, p, q, a) = (" << y << ", " << p << ", " << q << ", " << a << ")\n";
        std::cout << "Private key (x)          = " << x << "\n\n";
    }

    std::cout << "--- Signing document ---\n";
    sign_file_gost(doc_file, sig_file, x, p, q, a);

    std::cout << "--- Verifying signature ---\n";
    verify_file_gost(doc_file, sig_file, y, p, q, a);
}