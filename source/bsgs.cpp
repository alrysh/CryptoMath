#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <my_crypto_lib.hpp>
#include <random>
#include <unordered_map>

static bool mod_inverse_internal(uint64_t a, uint64_t m, uint64_t *inv) {
  if (m == 0 || m == 1)
    return false;
  a %= m;
  if (a == 0)
    return false;

  int64_t old_r = (int64_t)a, r = (int64_t)m;
  int64_t old_s = 1, s = 0;

  while (r != 0) {
    int64_t q = old_r / r;
    int64_t tmp;

    tmp = old_r - q * r;
    old_r = r;
    r = tmp;

    tmp = old_s - q * s;
    old_s = s;
    s = tmp;
  }

  if (old_r != 1)
    return false;

  old_s = ((old_s % (int64_t)m) + (int64_t)m) % (int64_t)m;
  *inv = (uint64_t)old_s;
  return true;
}

DlogResult baby_giant_step(uint64_t a, uint64_t y, uint64_t p) {
  DlogResult result{false, 0, 0, 0, 0};

  if (p < 2)
    return result;

  a %= p;
  y %= p;

  if (y == 1) {
    result.found = true;
    result.x = 0;
    return result;
  }

  if (y == 0) {
    if (a == 0) {
      result.found = true;
      result.x = 1;
    }
    return result;
  }

  uint64_t a_inv;
  if (!mod_inverse_internal(a, p, &a_inv)) {
    return result;
  }

  uint64_t m = (uint64_t)std::ceil(std::sqrt((double)p));
  result.m = m;

  std::unordered_map<uint64_t, uint64_t> baby_table;
  baby_table.reserve(m * 2);

  uint64_t cur = y;
  for (uint64_t j = 0; j < m; ++j) {
    if (baby_table.find(cur) == baby_table.end()) {
      baby_table[cur] = j;
    }
    cur = (uint64_t)((unsigned __int128)cur * a_inv % p);
    result.baby_steps++;
  }

  uint64_t a_m;
  fast_pow_mod(a, m, p, &a_m);

  cur = 1;
  for (uint64_t i = 0; i < m; ++i) {
    auto it = baby_table.find(cur);
    if (it != baby_table.end()) {
      uint64_t j = it->second;
      uint64_t x = i * m + j;

      uint64_t check;
      fast_pow_mod(a, x, p, &check);
      if (check == y) {
        result.found = true;
        result.x = x;
        return result;
      }
    }
    cur = (uint64_t)((unsigned __int128)cur * a_m % p);
    result.giant_steps++;
  }

  return result;
}

static uint64_t generate_prime(uint64_t p_min, uint64_t p_max) {
  std::random_device rd;
  std::mt19937_64 gen(rd());
  std::uniform_int_distribution<uint64_t> dist(p_min, p_max);

  uint64_t candidate;
  do {
    candidate = dist(gen);
    if (candidate % 2 == 0)
      candidate++;
  } while (!ferma(candidate));

  return candidate;
}

DlogResult baby_giant_step_generate(uint64_t p_min, uint64_t p_max) {
  uint64_t p = generate_prime(p_min, p_max);

  std::random_device rd;
  std::mt19937_64 gen(rd());

  std::uniform_int_distribution<uint64_t> dist_a(2, p - 2);
  uint64_t a = dist_a(gen);

  std::uniform_int_distribution<uint64_t> dist_x(1, p - 2);
  uint64_t x = dist_x(gen);

  uint64_t y;
  fast_pow_mod(a, x, p, &y);

  printf("Generated parameters\n");
  printf("  p = %llu\n", (unsigned long long)p);
  printf("  a = %llu\n", (unsigned long long)a);
  printf("  x = %llu\n", (unsigned long long)x);
  printf("  y = %llu\n\n", (unsigned long long)y);

  DlogResult res = baby_giant_step(a, y, p);
  res.x = x;
  return res;
}

DlogResult baby_giant_step_interactive() {
  int choice = 0;
  printf(":\n");
  printf("  1. Enter a, y, p\n");
  printf("  2. Generated parameters\n");
  printf("Choice: ");

  while (scanf("%d", &choice) != 1 || choice < 1 || choice > 2) {
    printf("Enter 1 or 2 ");
    while (getchar() != '\n')
      ;
  }

  if (choice == 1) {
    uint64_t a, y, p;
    printf("a = ");
    scanf("%llu", (unsigned long long *)&a);
    printf("y = ");
    scanf("%llu", (unsigned long long *)&y);
    printf("p = ");
    scanf("%llu", (unsigned long long *)&p);
    printf("\n");
    return baby_giant_step(a, y, p);
  }

  uint64_t p_min, p_max;
  printf("Min p: ");
  scanf("%llu", (unsigned long long *)&p_min);
  printf("Maxs p: ");
  scanf("%llu", (unsigned long long *)&p_max);
  printf("\n");

  if (p_min < 3)
    p_min = 3;
  if (p_max <= p_min)
    p_max = p_min + 1000;

  return baby_giant_step_generate(p_min, p_max);
}
