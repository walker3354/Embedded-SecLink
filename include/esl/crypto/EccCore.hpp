#pragma once
#include <memory>
#include <string>
#include <vector>
namespace esl::crypto {
    class EccCore {
        private:
            struct Impl;
            std::unique_ptr<Impl> m_impl;

            bool dev_mode;
            static constexpr size_t compressed_pk_size = 33;
            static constexpr size_t session_key_size = 32;
            static constexpr const char* key_load_path = "key.json";

            void generate_keys(uint16_t key_id);
            void load_key(uint16_t key_id);
            void save_key(uint16_t key_id);

        public:
            EccCore(uint16_t key_id, bool dev_mode = false);
            ~EccCore();
            // copy not allow
            EccCore(const EccCore&) = delete;
            EccCore& operator=(const EccCore&) = delete;
            // move define
            EccCore(EccCore&&) noexcept;
            EccCore& operator=(EccCore&&) noexcept;

            std::vector<uint8_t> get_public_key() const;
            std::vector<uint8_t> get_private_key() const;
            std::vector<uint8_t> get_compressed_public_key() const;

            std::string get_public_key_Hex() const;
            std::string get_private_key_Hex() const;
            std::string get_compressed_public_key_Hex() const;

            std::vector<uint8_t> ECDSA(const std::string& message) const;

            static bool verify_signature(const std::string& public_key_hex,
                                         const std::string& message,
                                         const std::vector<uint8_t>& signature);
            static bool verify_signature(const std::vector<uint8_t>& public_key,
                                         const std::string& message,
                                         const std::vector<uint8_t>& signature);

            std::vector<uint8_t> ECDH(
                const std::string& peer_public_key_hex) const;
            std::vector<uint8_t> ECDH(
                const std::vector<uint8_t>& peer_public_key) const;

            std::vector<uint8_t> symmetric_encrypt(
                const std::vector<uint8_t>& session_key,
                const std::string& message);

            std::string symmetric_decrypt(
                const std::vector<uint8_t>& session_key,
                const std::vector<uint8_t>& encrypted_data) const;

            std::vector<uint8_t> asymmetric_encrypt(
                const std::string& peer_public_key_hex,
                const std::string& message) const;
            std::vector<uint8_t> asymmetric_encrypt(
                const std::vector<uint8_t>& peer_public_key,
                const std::string& message) const;

            std::string asymmetric_decrypt(
                const std::vector<uint8_t>& encrypted_package) const;
    };
} // namespace esl::crypto