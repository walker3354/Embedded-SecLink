// examples/demo_app.cpp
#include <iostream>

#include "esl/crypto/BlsCore.hpp"

int main() {
    try {
        std::cout << "Initializing BLS Core..." << std::endl;
        esl::crypto::BlsCore bls(true); // 使用 dev_mode

        std::cout << "Secret Key: " << bls.get_secret_keyHex() << std::endl;
        std::cout << "Public Key: " << bls.get_public_keyHex() << std::endl;

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    return 0;
}
