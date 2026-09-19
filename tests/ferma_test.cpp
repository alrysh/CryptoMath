#include <my_crypto_lib.hpp>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
  if (argc < 2) {
    fprintf(stderr, "Bad format. Usage: ferma [val]\n");
    exit(EXIT_FAILURE);
  }
  uint64_t p = strtoull(argv[1], NULL, 10);
  if (ferma(p)) {
    printf("%ld is prime number\n", p);
  } else {
    printf("%ld is not prime number\n", p);
  }
  return 0;
}