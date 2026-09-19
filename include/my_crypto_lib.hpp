#ifndef MY_CRYPTO_LIB_HPP
#define MY_CRYPTO_LIB_HPP

#include <stdbool.h>
#include <stdint.h>

uint64_t prevention_overflow_mod(uint64_t a, uint64_t b, uint64_t mod);
int fast_pow_mod(uint64_t a, uint64_t exp, uint64_t mod, uint64_t *y);
int gcd(uint64_t a, uint64_t b, uint64_t *res);
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

#endif