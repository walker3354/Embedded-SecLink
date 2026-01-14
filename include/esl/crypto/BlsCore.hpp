#pragma once

#include <memory>
#include <string>
#include <vector>

namespace esl::crypto {
    class BlsCore {
        private:
            struct Impl;
            std::unique_ptr<Impl> keys; // avoid include BLS lib(reduce time)

            void generate_keys();
            void BlsCore::globalInit();

            bool dev_mode;

        public:
            BlsCore(bool dev_mode = false);
            ~BlsCore();

            BlsCore(const BlsCore&) = delete;
            BlsCore& operator=(const BlsCore&) = delete;

            BlsCore(const BlsCore&&) noexcept;
            BlsCore& operator=(BlsCore&&) noexcept;

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

            // same message signatures
            static bool verify_fast_aggregate_verify(
                const std::string& message, const std::string& aggSignatureHex,
                const std::string& aggPublicKeyHex);
            static bool verify_fast_aggregate_verify(
                const std::string& message, const std::string& aggSignatureHex,
                const std::vector<std::string>& publicKeysHex);

            // different message signatures
            static bool BlsCore::verify_aggregate_signature_distinct_messages(
                const std::vector<std::string>& messages,
                const std::vector<std::string>& publicKeysHex,
                const std::string& aggSignatureHex);
    };
}; // namespace esl::crypto