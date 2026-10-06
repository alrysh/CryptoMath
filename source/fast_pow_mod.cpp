#include <stdint.h>
#include <stdio.h>

uint64_t prevention_overflow_mod(uint64_t a, uint64_t b, uint64_t mod)
{
    if (mod == 0) return 0;
    return static_cast<uint64_t>((static_cast<__int128_t>(a) * b) % mod);
}



int fast_pow_mod(uint64_t a, uint64_t exp, uint64_t mod, uint64_t *y)
{
    if (!y) return -1;

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
    
    a %= mod;

    if (a == 0)
    {
        *y = 0;
        return 0;
    }

    *y = 1;
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

void fast_pow_mod_128(__int128_t base, __int128_t exp, __int128_t mod, __int128_t* res) {
    if (!res || mod == 0) return;
    __int128_t result = 1;
    base = base % mod;
    while (exp > 0) {
        if (exp % 2 == 1) {
            result = (result * base) % mod;
        }
        base = (base * base) % mod;
        exp /= 2;
    }
    *res = result;
}