#include "esl/crypto/BlsCore.hpp"

// 之後會用到 blst，現在先不 include 也能編譯
// #include <blst.h>

namespace esl::crypto {

    // Pimpl: 目前只是空殼，之後會放 blst_scalar / blst_p1 等等
    struct BlsCore::Impl {
            // 佔位符，之後會變成 blst_scalar secretKey; blst_p1 publicKey;
            int placeholder = 0;
    };

    BlsCore::BlsCore(bool dev_mode)
        : keys(std::make_unique<Impl>()), dev_mode(dev_mode) {
        // globalInit();    // 之後實作
        // generate_keys(); // 之後實作
    }

    BlsCore::~BlsCore() = default;

    void BlsCore::globalInit() {
        // TODO: blst_init or other setup
    }

    void BlsCore::generate_keys() {
        // TODO: blst_keygen
    }

    std::string BlsCore::get_public_keyHex() const {
        return "0xDEADBEEF"; // 佔位符
    }

    std::string BlsCore::get_secret_keyHex() const {
        if (dev_mode) {
            return "0xSECRET";
        }
        return "";
    }

    std::string BlsCore::bls_sign(const std::string& message) const {
        (void)message; // 避免 unused warning
        return "0xSIGNATURE";
    }

    bool BlsCore::bls_verify(const std::string& message,
                             const std::string& signatureHex,
                             const std::string& publicKeyHex) {
        (void)message;
        (void)signatureHex;
        (void)publicKeyHex;
        return false; // 空實作：總是失敗
    }

    std::string BlsCore::get_pop_proof() const {
        return bls_sign(get_public_keyHex());
    }

    bool BlsCore::verify_pop_proof(const std::string& pubKeysHex,
                                   const std::string& pop_proof) const {
        return bls_verify(pubKeysHex, pop_proof, pubKeysHex);
    }

    std::string BlsCore::aggregate_public_keys(
        const std::vector<std::string>& pubKeysHex) {
        (void)pubKeysHex;
        return "0xAGG_PK";
    }

    std::string BlsCore::aggregate_signatures(
        const std::vector<std::string>& signatures) {
        (void)signatures;
        return "0xAGG_SIG";
    }

    bool BlsCore::verify_fast_aggregate_verify(
        const std::string& message, const std::string& aggSignatureHex,
        const std::string& aggPublicKeyHex) {
        return bls_verify(message, aggSignatureHex, aggPublicKeyHex);
    }

    bool BlsCore::verify_fast_aggregate_verify(
        const std::string& message, const std::string& aggSignatureHex,
        const std::vector<std::string>& publicKeysHex) {
        std::string agg_pk = aggregate_public_keys(publicKeysHex);
        return bls_verify(message, aggSignatureHex, agg_pk);
    }

    bool BlsCore::verify_aggregate_signature_distinct_messages(
        const std::vector<std::string>& messages,
        const std::vector<std::string>& publicKeysHex,
        const std::string& aggSignatureHex) {
        (void)messages;
        (void)publicKeysHex;
        (void)aggSignatureHex;
        return false;
    }

} // namespace esl::crypto
