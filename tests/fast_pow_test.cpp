#include <stdio.h>
#include <stdlib.h>
#include <my_crypto_lib.hpp>
#include <limits.h>
#include <stdbool.h>

int main(int argc, char *argv[])
{
    if (argc < 3)
    {
        fprintf(stderr, "Bad format. Usage: fast_pow_mod [base] [exp] [mod]\n");
        exit(EXIT_FAILURE);
    }
    uint64_t y = 0;
    bool is_valid = fast_pow_mod(strtoull(argv[1], NULL, 10), strtoull(argv[2], NULL, 10), strtoull(argv[3], NULL, 10), &y);
    if (!is_valid)
        printf("y = %ld\n", y);
    else
        printf("result invalid\n");
    return 0;
}
