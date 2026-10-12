#include <iostream>
#include <my_crypto_lib.hpp>

int main(int argc, char** argv) {

    if (argc < 3) {
        std::cerr << "Error: Missing file arguments!\n";
        std::cerr << "Usage: " << argv[0] << " <input_file> <output_file>\n";
        return 1;
    }

    std::cout << "=== The Vernam encryption ===\n";

    std::string in_file = argv[1];
    std::string out_file = argv[2];
    vernam(in_file, out_file);
    std::cout << "Files done" << "\n";

    return 0;
}