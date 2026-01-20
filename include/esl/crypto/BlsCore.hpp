#pragma once

#include <memory>
#include <string>
#include <vector>

namespace esl::crypto {
    class BlsCore {
        private:
            struct Impl;
            std::unique_ptr<Impl> keys;
            bool dev_mode;
            constexpr static size_t IKM_LEN = 48;
            constexpr static size_t G1_COMPRESSED_SIZE = 48;
            constexpr static size_t SCALAR_SIZE = 32;
            constexpr static size_t G2_COMPRESSED_SIZE = 96;

            void generate_keys();

        public:
            BlsCore(bool dev_mode = false);
            ~BlsCore();

            // 暫時先禁用 copy/move（避免實作 move constructor）
            BlsCore(const BlsCore&) = delete;
            BlsCore& operator=(const BlsCore&) = delete;
            // BlsCore(BlsCore&&) noexcept;               // 先註解掉
            // BlsCore& operator=(BlsCore&&) noexcept;    // 先註解掉

            std::string get_public_keyHex() const;
            std::string get_secret_keyHex() const;
            std::string bls_sign(const std::string& message) const;

            static bool bls_verify(const std::string& message,
                                   const std::string& signatureHex,
                                   const std::string& publicKeyHex);

            std::string get_pop_proof() const;
            bool verify_pop_proof(const std::string& pubKeysHex,
                                  const std::string& pop_proof) const;

            static std::string aggregate_public_keys(
                const std::vector<std::string>& pubKeysHex);

            static std::string aggregate_signatures(
                const std::vector<std::string>& signatures);

            static bool verify_fast_aggregate_verify(
                const std::string& message, const std::string& aggSignatureHex,
                const std::string& aggPublicKeyHex);

            static bool verify_fast_aggregate_verify(
                const std::string& message, const std::string& aggSignatureHex,
                const std::vector<std::string>& publicKeysHex);

            static bool verify_aggregate_signature_distinct_messages(
                const std::vector<std::string>& messages,
                const std::vector<std::string>& publicKeysHex,
                const std::string& aggSignatureHex);
    };

} // namespace esl::crypto
