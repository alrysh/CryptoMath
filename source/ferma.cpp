#include <my_crypto_lib.hpp>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

bool ferma(uint64_t p) {
  if (p < 2) {
    return false;
  }
  if (p == 2) {
    return true;
  }
  srand(time(NULL));
  for (int i = 0; i < 100; i++) {
    uint64_t a = (rand() % (p - 2)) + 2;
    uint64_t gcn_res = 0;
    gcd(p, a, &gcn_res);
    if (gcn_res != 1) {
      return false;
    }
    uint64_t pow_res;
    fast_pow_mod(a, p - 1, p, &pow_res);
    if (pow_res != 1) {
      return false;
    }
  }
  return true;
}