#include <stdio.h>
#include <math.h>
#include <cstdint>
#include <random>
#include <iostream>
#include <vector>
#include <my_crypto_lib.hpp>


bool millerRabinTest(uint64_t n, int k = 20) {
    if (n < 2) return false;
    if (n == 2 || n == 3) return true;
    if ((n & 1) == 0) return false;

    static const uint64_t smallPrimes[] = {3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37};
    for (uint64_t p : smallPrimes) {
        if (n == p) return true;
        if (n % p == 0) return false;
    }

    uint64_t d = n - 1;
    int s = 0;
    while ((d & 1) == 0) {
        d >>= 1;
        s++;
    }

    static std::random_device rd;
    static std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint64_t> dis(2, n - 2);

    for (int i = 0; i < k; ++i) {
        uint64_t a = dis(gen);
        uint64_t x;
        fast_pow_mod(a, d, n, &x);

        if (x == 1 || x == n - 1) {
            continue;
        }

        bool composite = true;
        for (int r = 1; r < s; ++r) {
            x = prevention_overflow_mod(x, x, n); 
            if (x == n - 1) {
                composite = false;
                break;
            }
            if (x == 1) {
                return false;
            }
        }

        if (composite) {
            return false;
        }
    }

    return true;
}

uint64_t getRandom64(uint64_t min_val, uint64_t max_val) {
    static std::random_device rd;
    static std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint64_t> dis(min_val, max_val);
    return dis(gen);
}

uint64_t generate_p(uint64_t *out_q) {
    while (true) {
        // случайное нечетное q (ограничить диапазон, чтобы 2q + 1 не переполнило uint64)
        uint64_t q = getRandom64(100000000ULL, 0x7FFFFFFFFFFFFFFFULL) | 1;

        if (millerRabinTest(q)) {
            uint64_t p = 2 * q + 1;
            if (millerRabinTest(p)) {
                // q пригодится для генерации g
                if (out_q) *out_q = q; 
                return p;
            }
        }
    }
}

uint64_t generate_g(uint64_t p, uint64_t q) {
    // Перебираем g начиная с 2. 
    // для безопасного простого p = 2q + 1 достаточно проверить g^2 != 1 и g^q != 1 (mod p)
    for (uint64_t g = 2; g < p; ++g) {
        uint64_t res1, res2;
        fast_pow_mod(g, 2, p, &res1);
        fast_pow_mod(g, q, p, &res2);

        if (res1 != 1 && res2 != 1) {
            return g;
        }
    }
    return 2;
}

bool check_users_args(uint64_t num) { //
    return millerRabinTest(num);
}

uint64_t build_key(bool user_input) {
    uint64_t p, g, a, b;
    uint64_t q = 0;

    if (user_input) {
        std::cout << "Enter args: p, g, a, b: ";
        std::vector<uint64_t> input(4);
        for (size_t i = 0; i < 4; i++) {
            std::cin >> input[i];
        }
        
        p = input[0];
        g = input[1];
        a = input[2];
        b = input[3];

        if (!check_users_args(p)) {
            std::cout << "Warning: Input p is not prime!\n";
        }

    } else {
        std::cout << "Genearate safe prime p and g...\n";
        p = generate_p(&q);
        g = generate_g(p, q);

        a = getRandom64(2, p - 2);
        b = getRandom64(2, p - 2);

        std::cout << "p = " << p << "\n";
        std::cout << "g = " << g << "\n";
        std::cout << "a (private Alice) = " << a << "\n";
        std::cout << "b (private Bob)   = " << b << "\n\n";
    }

    uint64_t A, B, K1, K2;

    fast_pow_mod(g, a, p, &A);
    fast_pow_mod(g, b, p, &B);

    std::cout << "Open key Alice (A) = " << A << "\n";
    std::cout << "Open key Bob (B) = " << B << "\n";

    fast_pow_mod(B, a, p, &K1);
    fast_pow_mod(A, b, p, &K2);

    if (K1 != K2) {
        std::cerr << " Error: Keys not equal! K1 = " << K1 << ", K2 = " << K2 << "\n";
        return 0;
    }

    std::cout << "Success! Common key found.\n";
    return K1;
}