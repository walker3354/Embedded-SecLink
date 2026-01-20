#include "esl/crypto/BlsCore.hpp"

#include <blst.h>

#include <array>
#include <cstring>
#include <iomanip>
#include <sstream>
#include <stdexcept>

#include "esl/utils/Random.hpp"

using namespace std;
using namespace esl;

namespace esl::crypto {
    struct BlsCore::Impl {
            blst_scalar secret_key;
            blst_p1 public_key;
    };

    BlsCore::BlsCore(bool dev_mode)
        : keys(std::make_unique<Impl>()), dev_mode(dev_mode) {
        generate_keys();
    }

    BlsCore::~BlsCore() = default;

    void BlsCore::generate_keys() {
        array<uint8_t, BlsCore::IKM_LEN> ikm;
        utils::Random rand(0, 255);
        for (auto& bytes : ikm) {
            bytes = static_cast<uint8_t>(rand.get_random_int());
        }

        const char* info_str = "ESL-BLS12381-KEYGEN";
        blst_keygen(&keys->secret_key, ikm.data(), ikm.size(),
                    reinterpret_cast<const uint8_t*>(info_str),
                    strlen(info_str));
        blst_sk_to_pk_in_g1(&keys->public_key, &keys->secret_key);
        memset(ikm.data(), 0, ikm.size());
    }

    string bytes_to_hex(const uint8_t* data, size_t len) {
        stringstream ss;
        ss << "0x" << hex << setfill('0');
        for (size_t i = 0; i < len; ++i) {
            ss << setw(2) << static_cast<int>(data[i]);
        }
        return ss.str();
    }

    string BlsCore::get_public_keyHex() const {
        blst_p1_affine pk_affine;
        blst_p1_to_affine(&pk_affine, &keys->public_key);
        array<uint8_t, BlsCore::G1_COMPRESSED_SIZE> compressed;
        blst_p1_affine_compress(compressed.data(), &pk_affine);
        return bytes_to_hex(compressed.data(), compressed.size());
    }

    string BlsCore::get_secret_keyHex() const {
        if (dev_mode == false) return "";

        array<uint8_t, BlsCore::SCALAR_SIZE> sk_bytes;
        blst_bendian_from_scalar(sk_bytes.data(), &keys->secret_key);
        return bytes_to_hex(sk_bytes.data(), sk_bytes.size());
    }

    string BlsCore::bls_sign(const string& message) const {
        const char* DST = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";
        blst_p2 hash_point;
        blst_hash_to_g2(&hash_point,
                        reinterpret_cast<const uint8_t*>(message.data()),
                        message.size(), reinterpret_cast<const uint8_t*>(DST),
                        std::strlen(DST), nullptr, 0);
        blst_p2 signature;
        blst_sign_pk_in_g1(&signature, &hash_point, &keys->secret_key);
        blst_p2_affine sig_affine;
        blst_p2_to_affine(&sig_affine, &signature);

        array<uint8_t, BlsCore::G2_COMPRESSED_SIZE> compressed;
        blst_p2_affine_compress(compressed.data(), &sig_affine);
        return bytes_to_hex(compressed.data(), compressed.size());
    }

    bool BlsCore::bls_verify(const string& message, const string& signatureHex,
                             const string& publicKeyHex) {
        return false;
    }

    string BlsCore::get_pop_proof() const {
        return bls_sign(get_public_keyHex());
    }

    bool BlsCore::verify_pop_proof(const string& pubKeysHex,
                                   const string& pop_proof) const {
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
