#include <iostream>
#include <my_crypto_lib.hpp>

int main() {
    std::cout << "=== The Diffie-Hellman system ===\n";
    std::cout << "Select the mode: 0 - Automatic generation, 1 - User input: ";
    bool mode;
    std::cin >> mode;

    uint64_t secret_key = build_key(mode);
    std::cout << "The final shared key (K) = " << secret_key << "\n";

    return 0;
}