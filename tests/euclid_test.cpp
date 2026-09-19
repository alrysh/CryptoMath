#include <my_crypto_lib.hpp>
#include <stdio.h>
#include <stdlib.h>

int main() {
  uint64_t x, y, res_gcd;

  if (egcd(&x, &y, &res_gcd) == -1) {
    exit(EXIT_FAILURE);
  }
  printf("x = %ld, y = %ld, res_gcd = %ld\n", x, y, res_gcd);
  return 0;
}