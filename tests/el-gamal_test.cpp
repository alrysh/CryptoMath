#include <iostream>
#include <my_crypto_lib.hpp>

int main(int argc, char** argv) {

    if (argc < 3) {
        std::cerr << "Error: Missing file arguments!\n";
        std::cerr << "Usage: " << argv[0] << " <input_file> <output_file>\n";
        return 1;
    }

    std::cout << "=== The El Gamal encryption ===\n";
    std::cout << "Select the mode: 0 - Automatic generation, 1 - User input: ";
    bool mode;
    std::cin >> mode;

    std::string in_file = argv[1];
    std::string out_file = argv[2];
    elgamal_key(mode, in_file, out_file);
    std::cout << "Files done" << "\n";

    return 0;
}