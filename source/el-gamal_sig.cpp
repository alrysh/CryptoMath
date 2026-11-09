#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cstdint>
#include <cstring>
#include <iomanip>

#include <openssl/evp.h>
#include <my_crypto_lib.hpp>

uint64_t find_primitive_root(uint64_t p, uint64_t q) {
    for (uint64_t g = 2; g < p; ++g) {
        __int128_t res1 = 0;
        __int128_t res2 = 0;
        fast_pow_mod_128(g, 2, p, &res1);
        fast_pow_mod_128(g, q, p, &res2);
        if (res1 != 1 && res2 != 1) {
            return g;
        }
    }
    return 2;
}

uint64_t generate_k_elgamal(uint64_t p) {
    while (true) {
        uint64_t k = getRandom64(2, p - 2);
        __int128_t gcd_val = 0;
        gcd_128(k, p - 1, &gcd_val);
        if (gcd_val == 1) {
            return k;
        }
    }
}

bool sign_file_elgamal(const std::string& doc_path, const std::string& sig_path,
                       uint64_t x, uint64_t p, uint64_t g) {
    std::vector<uint8_t> hash = compute_file_hash_sha256(doc_path);
    if (hash.empty()) return false;

    std::cout << "[+] Calculated Hash: ";
    print_hex_digest(hash);

    std::ofstream sig_out(sig_path, std::ios::binary);
    if (!sig_out.is_open()) return false;

    for (uint8_t byte_val : hash) {
        uint64_t m = byte_val;
        uint64_t r = 0;
        uint64_t s = 0;

        while (true) {
            uint64_t k = generate_k_elgamal(p);
            
            __int128_t r_128 = 0;
            fast_pow_mod_128(g, k, p, &r_128);
            r = static_cast<uint64_t>(r_128);

            __int128_t xr = (static_cast<__int128_t>(x) * r) % (p - 1);
            __int128_t u = (static_cast<__int128_t>(m) - xr) % (p - 1);
            if (u < 0) {
                u += (p - 1);
            }

            uint64_t k_inv = advanced_euclid(k, p - 1);
            __int128_t s_128 = (static_cast<__int128_t>(k_inv) * u) % (p - 1);
            s = static_cast<uint64_t>(s_128);

            if (s != 0) {
                break;
            }
        }

        sig_out.write(reinterpret_cast<const char*>(&r), sizeof(r));
        sig_out.write(reinterpret_cast<const char*>(&s), sizeof(s));
    }

    sig_out.close();
    return true;
}

bool verify_file_elgamal(const std::string& doc_path, const std::string& sig_path,
                         uint64_t y, uint64_t p, uint64_t g) {
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

        if (r <= 0 || r >= p || s <= 0 || s >= (p - 1)) {
            sig_in.close();
            std::cout << "[FAIL] Signature values out of range!\n\n";
            return false;
        }

        uint64_t m = current_hash[i];

        __int128_t yr = 0;
        fast_pow_mod_128(y, r, p, &yr);

        __int128_t rs = 0;
        fast_pow_mod_128(r, s, p, &rs);

        __int128_t left = (yr * rs) % p;

        __int128_t right = 0;
        fast_pow_mod_128(g, m, p, &right);

        if (left != right) {
            sig_in.close();
            std::cout << "[FAIL] Signature is INVALID for byte " << i << "!\n\n";
            return false;
        }
    }

    sig_in.close();
    std::cout << "[SUCCESS] Signature is VALID!\n\n";
    return true;
}

void elgamal_signature(bool user_input, const std::string& doc_file, const std::string& sig_file) {
    uint64_t p = 0, q = 0, g = 0, x = 0, y = 0;

    if (user_input) {
        std::cout << "Enter args (p, g, x): ";
        std::cin >> p >> g >> x;

        if (!check_users_args(p)) {
            std::cout << "Warning: Input p is not prime!\n";
        }

        __int128_t y_128 = 0;
        fast_pow_mod_128(g, x, p, &y_128);
        y = static_cast<uint64_t>(y_128);

        std::cout << "Calculated public key y = " << y << "\n\n";
    } else {
        p = generate_p_rsa(&q);
        g = find_primitive_root(p, q);
        x = getRandom64(2, p - 2);

        __int128_t y_128 = 0;
        fast_pow_mod_128(g, x, p, &y_128);
        y = static_cast<uint64_t>(y_128);

        std::cout << "p = " << p << "\n";
        std::cout << "g = " << g << "\n";
        std::cout << "Public key  (y, p, g) = (" << y << ", " << p << ", " << g << ")\n";
        std::cout << "Private key (x)       = " << x << "\n\n";
    }

    std::cout << "--- Signing document ---\n";
    sign_file_elgamal(doc_file, sig_file, x, p, g);

    std::cout << "--- Verifying signature ---\n";
    verify_file_elgamal(doc_file, sig_file, y, p, g);
}