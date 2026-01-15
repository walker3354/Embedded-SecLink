#pragma once
#include <memory>
#include <string>
#include <vector>
namespace esl::crypto {
    class EccCore {
        private:
            struct Impl;
            std::unique_ptr<Impl> m_impl;

            void generate_keys();

        public:
            EccCore(bool dev_mode = false);
            ~EccCore();
            // copy not allow
            EccCore(const EccCore&) = delete;
            EccCore& operator=(const EccCore&) = delete;
            // move define
            EccCore(EccCore&&) noexcept;
            EccCore& operator=(EccCore&&) noexcept;

            std::vector<uint8_t> get_public_key() const;
            std::vector<uint8_t> get_private_key() const;

            std::string get_public_key_Hex() const;
            std::string get_private_key_Hex() const;

            std::vector<uint8_t> ECDSA(
                const std::vector<uint8_t>& message_hash) const;
            static bool verify_signature(
                const std::vector<uint8_t>& public_key,
                const std::vector<uint8_t>& message_hash,
                const std::vector<uint8_t>& signature);
        };
} // namespace esl::crypto