#pragma once

#include <memory>
#include <string>
#include <vector>

namespace esl::crypto {
    class BlsCore {
        private:
            struct Impl;
            std::unique_ptr<Impl> keys;

            void generate_keys();
            void BlsCore::globalInit();

            bool dev_mode;

        public:
            BlsCore(bool dev_mode = false);
            ~BlsCore();

            BlsCore(const BlsCore&) = delete;
            BlsCore& operator=(const BlsCore&) = delete;

            std::string get_public_keyHex() const;
            std::string get_secret_keyHex() const;

            std::string bls_sign(const std::string& message) const;
            static bool bls_verify(const std::string& message,
                                   const std::string& signatureHex,
                                   const std::string& publicKeyHex);
    };
} // namespace esl::crypto