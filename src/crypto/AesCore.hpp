#pragma once
#include <cstdint>
#include <vector>

namespace esl::crypto {
    class AesCore {
        private:
        public:
            static constexpr size_t BLOCK_SIZE = 16;
            static constexpr size_t KEY_SIZE = 16; // AES-128
            static constexpr size_t IV_SIZE = 16;

            static std::vector<uint8_t> encrypt_cbc(
                const std::vector<uint8_t>& plaintext,
                const std::vector<uint8_t>& key,
                const std::vector<uint8_t>& iv);

            static std::vector<uint8_t> decrypt_cbc(
                const std::vector<uint8_t>& ciphertext,
                const std::vector<uint8_t>& key,
                const std::vector<uint8_t>& iv);
    };
} // namespace esl::crypto