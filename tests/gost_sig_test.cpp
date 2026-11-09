#include <iostream>
#include <my_crypto_lib.hpp>

int main(int argc, char** argv) {
    if (argc < 3) {
        std::cerr << "Error: Missing file arguments!\n";
        std::cerr << "Usage: " << argv[0] << " <input_file> <signature_file>\n";
        return 1;
    }

    std::cout << "=== GOST R 34.10-94 Digital Signature ===\n";
    std::cout << "Select the mode: 0 - Automatic generation, 1 - User input: ";
    bool mode;
    std::cin >> mode;

    std::string in_file = argv[1];
    std::string sig_file = argv[2];

    gost_signature(mode, in_file, sig_file);

    std::cout << "Files done\n";

    return 0;
}