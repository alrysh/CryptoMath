#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cstdint>
#include <cstring>
#include <iomanip>

#include <openssl/evp.h>
#include <my_crypto_lib.hpp>

std::vector<uint8_t> compute_file_hash_sha256(const std::string& filepath) {
    std::ifstream file(filepath, std::ios::binary);
    if (!file.is_open()) {
        return {};
    }

    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    const EVP_MD* md = EVP_sha256();
    
    EVP_DigestInit_ex(mdctx, md, nullptr);

    char buffer[4096];
    while (file.read(buffer, sizeof(buffer))) {
        EVP_DigestUpdate(mdctx, buffer, file.gcount());
    }
    if (file.gcount() > 0) {
        EVP_DigestUpdate(mdctx, buffer, file.gcount());
    }

    std::vector<uint8_t> hash(EVP_MD_size(md));
    unsigned int hash_len = 0;
    EVP_DigestFinal_ex(mdctx, hash.data(), &hash_len);
    EVP_MD_CTX_free(mdctx);

    return hash;
}

void print_hex_digest(const std::vector<uint8_t>& digest) {
    for (uint8_t b : digest) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
    }
    std::cout << std::dec << "\n";
}

__int128_t generate_pair_gcd_128(__int128_t phi) {
    if (phi <= 3) return 0;
    
    while (true) {
        uint64_t val = getRandom64(3, 65537);
        if (val % 2 == 0) val++;
        
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
            if (millerRabinTest(q, 20)) {
                if (out_q != nullptr) {
                    *out_q = q;
                }
                return p;
            }
        }
    }
}

bool sign_file_rsa(const std::string& doc_path, const std::string& sig_path,
                   uint64_t c, uint64_t N) {
    
    std::vector<uint8_t> hash = compute_file_hash_sha256(doc_path);
    if (hash.empty()) return false;

    std::cout << "[+] Calculated Hash: ";
    print_hex_digest(hash);

    std::ofstream sig_out(sig_path, std::ios::binary);
    if (!sig_out.is_open()) {
        return false;
    }

    for (uint8_t byte_val : hash) {
        uint64_t m = byte_val;
        __int128_t s = 0;
        fast_pow_mod_128(m, c, N, &s);
        uint64_t sig_chunk = static_cast<uint64_t>(s);
        sig_out.write(reinterpret_cast<const char*>(&sig_chunk), sizeof(sig_chunk));
    }

    sig_out.close();
    return true;
}

bool verify_file_rsa(const std::string& doc_path, const std::string& sig_path,
                     uint64_t d, uint64_t N) {
    
    std::vector<uint8_t> current_hash = compute_file_hash_sha256(doc_path);
    if (current_hash.empty()) return false;

    std::ifstream sig_in(sig_path, std::ios::binary);
    if (!sig_in.is_open()) {
        return false;
    }

    std::vector<uint8_t> recovered_hash;
    uint64_t s_chunk = 0;

    while (sig_in.read(reinterpret_cast<char*>(&s_chunk), sizeof(s_chunk))) {
        __int128_t w = 0;
        fast_pow_mod_128(s_chunk, d, N, &w);
        recovered_hash.push_back(static_cast<uint8_t>(w));
    }
    sig_in.close();

    std::cout << "[*] Current doc hash:   ";
    print_hex_digest(current_hash);
    std::cout << "[*] Hash from signature: ";
    print_hex_digest(recovered_hash);

    if (current_hash == recovered_hash) {
        std::cout << "[SUCCESS] Signature is VALID!\n\n";
        return true;
    } else {
        std::cout << "[FAIL] Signature is INVALID!\n\n";
        return false;
    }
}

void rsa_signature(bool user_input, const std::string& doc_file, const std::string& sig_file) {
    uint64_t p = 0, q = 0, N = 0, d = 0, c = 0;
    __int128_t f = 0;

    if (user_input) {
        std::cout << "Enter args (p, q, d): ";
        std::cin >> p >> q >> d;

        N = p * q;
        f = static_cast<__int128_t>(p - 1) * (q - 1);

        if (!check_users_args(p) || !check_users_args(q)) {
            std::cout << "Warning: Input p or q is not prime!\n";
        }

        c = advanced_euclid(d, f);
        std::cout << "Calculated c = " << c << "\n\n";
    } else {
        p = generate_p_rsa(nullptr);
        q = generate_p_rsa(nullptr);

        N = p * q;
        f = static_cast<__int128_t>(p - 1) * (q - 1);

        d = generate_pair_gcd_128(f);
        c = advanced_euclid(d, f);

        std::cout << "p = " << p << "\n";
        std::cout << "q = " << q << "\n";
        std::cout << "N = " << N << "\n";
        std::cout << "d = " << d << "\n";
        std::cout << "c = " << c << "\n\n";
    }

    std::cout << "--- Signing document ---\n";
    sign_file_rsa(doc_file, sig_file, c, N);

    std::cout << "--- Verifying signature ---\n";
    verify_file_rsa(doc_file, sig_file, d, N);
}