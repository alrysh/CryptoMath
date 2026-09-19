#include <my_crypto_lib.hpp>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

int gcd(uint64_t a, uint64_t b, uint64_t *res) {
  if (a < b) {
    fprintf(stderr, "Euclid's algorithm requires that a >= b\n");
    return -1;
  }
  uint64_t cur = 0;
  while (b != 0) {
    cur = a % b;
    a = b;
    b = cur;
  }
  *res = a;
  return 0;
}

int egcd(uint64_t *x, uint64_t *y, uint64_t *res_gcd) {
  uint64_t a, b;
  printf("Choose the option for A and B:\n1. Console input\n2. Random\n3. "
         "Randon with ferma test\nYour choice:  \b\b");
  int choice = 0;
  while (scanf("%d", &choice) != 1 || choice < 0 || choice > 3) {
    fprintf(stderr, "Please choose option 1-3\n");
  }
  switch (choice) {
  case 1:
    printf("a = \b");
    scanf("%ld", &a);
    printf("b = \b");
    scanf("%ld", &b);
    break;
  case 2:
    a = rand() + 1;
    b = rand() + 1;
    printf("a = %ld, b = %ld\n", a, b);
    break;
  case 3:
    a = rand() + 1;
    b = rand() + 1;
    while (!ferma(a) && !ferma(b)) {
      a = rand() + 1;
      b = rand() + 1;
    }
    printf("a = %ld, b = %ld\n", a, b);
    break;
  }
  if (a < b) {
    fprintf(stderr, "Extended Euclid's algorithm requres that a >= b");
    return -1;
  }
  uint64_t u[3] = {a, 1, 0};
  uint64_t v[3] = {b, 0, 1};
  uint64_t t[3] = {0};
  uint64_t q;
  while (v[0] != 0) {
    q = u[0] / v[0];
    t[0] = u[0] % v[0];
    t[1] = u[1] - q * v[1];
    t[2] = u[2] - q * v[2];
    for (int i = 0; i < 3; i++) {
      u[i] = v[i];
      v[i] = t[i];
    }
  }
  *res_gcd = u[0];
  *x = u[1];
  *y = u[2];
  return 0;
}
