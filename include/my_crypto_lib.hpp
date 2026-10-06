#ifndef MY_CRYPTO_LIB_HPP
#define MY_CRYPTO_LIB_HPP

#include <stdbool.h>
#include <stdint.h>
#include <string>

uint64_t prevention_overflow_mod(uint64_t a, uint64_t b, uint64_t mod);
int fast_pow_mod(uint64_t a, uint64_t exp, uint64_t mod, uint64_t *y);
void fast_pow_mod_128(__int128_t base, __int128_t exp, __int128_t mod, __int128_t* res);
int gcd(uint64_t a, uint64_t b, uint64_t *res);
__int128_t gcd_128(__int128_t a, __int128_t b,__int128_t *res);
int egcd(uint64_t *x, uint64_t *y, uint64_t *res_gcd);
bool ferma(uint64_t p);

#include <cstdint>

struct DlogResult {
  bool found;
  uint64_t x;
  uint64_t m;
  uint64_t baby_steps;
  uint64_t giant_steps;
};

DlogResult baby_giant_step(uint64_t a, uint64_t y, uint64_t p);

DlogResult baby_giant_step_interactive();

DlogResult baby_giant_step_generate(uint64_t p_min, uint64_t p_max);

// 3 
bool millerRabinTest(uint64_t n, int k);
uint64_t getRandom64(uint64_t min_val, uint64_t max_val); //
uint64_t generate_p(uint64_t *out_q);
uint64_t generate_g(uint64_t p, uint64_t q);
bool check_users_args(uint64_t num);
uint64_t build_key(bool user_input);

// 4. Shamir

void stream_file(const std::string& infile, const std::string& outfile, 
                 uint64_t p, uint64_t Ca, uint64_t Da, uint64_t Cb, uint64_t Db);
uint64_t generate_C(uint64_t p);
uint64_t advanced_euclid(uint64_t c, uint64_t mod_val);
uint64_t shamir(uint64_t m, uint64_t p, uint64_t Ca, uint64_t Da, uint64_t Cb, uint64_t Db);
void shamir_key(bool user_input, std::string& in, std::string& out);

// 5

struct ElGamalCiphertext {
    uint64_t a;
    uint64_t b;
};

uint64_t find_primitive_root(uint64_t p);
uint64_t generate_k(uint64_t p);

ElGamalCiphertext elgamal_encrypt(uint64_t m, uint64_t p, uint64_t g, uint64_t y);
uint64_t elgamal_decrypt(const ElGamalCiphertext& cipher, uint64_t p, uint64_t x);
uint64_t elgamal_process_block(uint64_t m, uint64_t p, uint64_t g, uint64_t y, uint64_t x);

void stream_file_elgamal(const std::string& infile, const std::string& outfile, 
                         uint64_t p, uint64_t g, uint64_t y, uint64_t x);
void elgamal_key(bool user_input, std::string& in, std::string& out);

void rsa(bool user_input, std::string& in, std::string& out);
void stream_file_rsa(const std::string& infile, const std::string& outfile, 
                    uint64_t Db, uint64_t Cb, uint64_t N);
__int128_t generate_pair_gcd_128(__int128_t phi);


#endif