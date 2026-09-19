#include <stdint.h>
#include <stdio.h>

uint64_t prevention_overflow_mod(uint64_t a, uint64_t b, uint64_t mod)
{
    return ((uint64_t)((__int128_t)a * b) % mod);
}

int fast_pow_mod(uint64_t a, uint64_t exp, uint64_t mod, uint64_t *y)
{
    if (mod == 0)
    {
        fprintf(stderr, "division by zero\n");
        return -1;
    }
    if (mod == 1)
    {
        *y = 0;
        return 0;
    }
    if (exp == 0)
    {
        *y = 1;
        return 0;
    }
    *y = 1;
    a %= mod;
    while (exp > 0)
    {
        if (exp & 1)
        {
            *y = prevention_overflow_mod(*y, a, mod);
        }
        a = prevention_overflow_mod(a, a, mod);
        exp >>= 1;
    }
    return 0;
}