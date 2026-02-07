#include "esl/crypto/BlsCore.hpp"

#include <blst.h>

#include <array>
#include <cstring>
#include <iomanip>
#include <sstream>
#include <stdexcept>

#include "esl/utils/Random.hpp"
#include "esl/utils/json.hpp"

using namespace std;
using namespace esl;

namespace {
    string bytes_to_hex(const uint8_t* data, size_t len) {
        stringstream ss;
        ss << "0x" << hex << setfill('0');
        for (size_t i = 0; i < len; ++i) {
            ss << setw(2) << static_cast<int>(data[i]);
        }
        return ss.str();
    }

    static vector<uint8_t> hex_to_bytes(const string& hex) {
        string hex_clean = hex;
        if (hex_clean.size() >= 2 && hex_clean[0] == '0' &&
            hex_clean[1] == 'x') {
            hex_clean = hex_clean.substr(2);
        }

        if (hex_clean.size() % 2 != 0)
            throw invalid_argument("Hex string must have even length");

        vector<uint8_t> bytes;
        bytes.reserve(hex_clean.size() / 2);

        for (size_t i = 0; i < hex_clean.size(); i += 2) {
            string byte_str = hex_clean.substr(i, 2);
            uint8_t byte = static_cast<uint8_t>(stoi(byte_str, nullptr, 16));
            bytes.push_back(byte);
        }
        return bytes;
    }
} // namespace

namespace esl::crypto {
    struct BlsCore::Impl {
            blst_scalar secret_key;
            blst_p1 public_key;
    };

    BlsCore::BlsCore(bool dev_mode)
        : keys(make_unique<Impl>()), dev_mode(dev_mode) {
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
                        strlen(DST), nullptr, 0);
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
        try {
            vector<uint8_t> pk_bytes = hex_to_bytes(publicKeyHex);
            if (pk_bytes.size() != BlsCore::G1_COMPRESSED_SIZE) return false;

            blst_p1_affine pk_affine;
            if (blst_p1_uncompress(&pk_affine, pk_bytes.data()) != BLST_SUCCESS)
                return false;

            vector<uint8_t> sig_bytes = hex_to_bytes(signatureHex);
            if (sig_bytes.size() != BlsCore::G2_COMPRESSED_SIZE) return false;

            blst_p2_affine sig_affine;
            if (blst_p2_uncompress(&sig_affine, sig_bytes.data()) !=
                BLST_SUCCESS)
                return false;

            if (!blst_p2_affine_in_g2(&sig_affine)) return false;

            const char* DST = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";
            blst_p2 hash_point;
            blst_hash_to_g2(
                &hash_point, reinterpret_cast<const uint8_t*>(message.data()),
                message.size(), reinterpret_cast<const uint8_t*>(DST),
                strlen(DST), nullptr, 0);

            return blst_core_verify_pk_in_g1(
                       &pk_affine, &sig_affine, true,
                       reinterpret_cast<const uint8_t*>(message.data()),
                       message.size(), reinterpret_cast<const uint8_t*>(DST),
                       strlen(DST), nullptr, 0) == BLST_SUCCESS;
        } catch (...) {
            return false;
        }
    }

    string BlsCore::get_pop_proof() const {
        return bls_sign(get_public_keyHex());
    }

    bool BlsCore::verify_pop_proof(const string& pubKeysHex,
                                   const string& pop_proof) const {
        return bls_verify(pubKeysHex, pop_proof, pubKeysHex);
    }

    string BlsCore::aggregate_public_keys(const vector<string>& pubKeysHex) {
        if (pubKeysHex.empty()) throw invalid_argument("empty pk vector");

        blst_p1 agg_pk;
        {
            vector<uint8_t> pk_bytes = hex_to_bytes(pubKeysHex[0]);
            if (pk_bytes.size() != G1_COMPRESSED_SIZE)
                throw invalid_argument("Invalid public key size");
            blst_p1_affine pk_affine;

            if (blst_p1_uncompress(&pk_affine, pk_bytes.data()) != BLST_SUCCESS)
                throw invalid_argument("Failed to decompress public key");
            blst_p1_from_affine(&agg_pk, &pk_affine);
        }

        for (size_t i = 1; i < pubKeysHex.size(); ++i) {
            auto pk_bytes = hex_to_bytes(pubKeysHex[i]);
            if (pk_bytes.size() != G1_COMPRESSED_SIZE)
                throw invalid_argument("Invalid public key size");

            blst_p1_affine pk_affine;
            if (blst_p1_uncompress(&pk_affine, pk_bytes.data()) != BLST_SUCCESS)
                throw invalid_argument("Failed to decompress public key");
            blst_p1_add_or_double_affine(&agg_pk, &agg_pk, &pk_affine);
        }

        blst_p1_affine agg_pk_affine;
        blst_p1_to_affine(&agg_pk_affine, &agg_pk);
        array<uint8_t, G1_COMPRESSED_SIZE> compressed;
        blst_p1_affine_compress(compressed.data(), &agg_pk_affine);
        return bytes_to_hex(compressed.data(), compressed.size());
    }

    string BlsCore::aggregate_signatures(const vector<string>& signatures) {
        if (signatures.empty())
            throw invalid_argument("signatures vector is empty");

        blst_p2 agg_sig;
        {
            vector<uint8_t> sig_bytes = hex_to_bytes(signatures[0]);
            if (sig_bytes.size() != G2_COMPRESSED_SIZE)
                throw runtime_error("signature compress error");
            blst_p2_affine sig_affine;
            if (blst_p2_uncompress(&sig_affine, sig_bytes.data()) !=
                BLST_SUCCESS)
                throw runtime_error("signature uncompress error");
            blst_p2_from_affine(&agg_sig, &sig_affine);
        }

        for (size_t i = 1; i < signatures.size(); ++i) {
            vector<uint8_t> sig_bytes = hex_to_bytes(signatures[i]);
            if (sig_bytes.size() != G2_COMPRESSED_SIZE)
                throw runtime_error("signature compress error");

            blst_p2_affine sig_affine;
            if (blst_p2_uncompress(&sig_affine, sig_bytes.data()) !=
                BLST_SUCCESS)
                throw runtime_error("signature uncompress error");
            blst_p2_add_or_double_affine(&agg_sig, &agg_sig, &sig_affine);
        }
        blst_p2_affine agg_sig_affine;
        blst_p2_to_affine(&agg_sig_affine, &agg_sig);
        array<uint8_t, G2_COMPRESSED_SIZE> compressed;
        blst_p2_affine_compress(compressed.data(), &agg_sig_affine);
        return bytes_to_hex(compressed.data(), compressed.size());
    }

    bool BlsCore::verify_fast_aggregate_verify(const string& message,
                                               const string& aggSignatureHex,
                                               const string& aggPublicKeyHex) {
        return bls_verify(message, aggSignatureHex, aggPublicKeyHex);
    }

    bool BlsCore::verify_fast_aggregate_verify(
        const string& message, const string& aggSignatureHex,
        const vector<string>& publicKeysHex) {
        string agg_pk = aggregate_public_keys(publicKeysHex);
        return bls_verify(message, aggSignatureHex, agg_pk);
    }

    bool BlsCore::verify_aggregate_signature_distinct_messages(
        const vector<string>& messages, const vector<string>& publicKeysHex,
        const string& aggSignatureHex) {
        if (messages.empty() || publicKeysHex.empty()) {
            return false;
        }
        if (messages.size() != publicKeysHex.size()) {
            return false;
        }

        try {
            const char* DST = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";
            auto sig_bytes = hex_to_bytes(aggSignatureHex);
            if (sig_bytes.size() != G2_COMPRESSED_SIZE) {
                return false;
            }

            blst_p2_affine agg_sig_affine;
            if (blst_p2_uncompress(&agg_sig_affine, sig_bytes.data()) !=
                BLST_SUCCESS) {
                return false;
            }
            if (!blst_p2_affine_in_g2(&agg_sig_affine)) {
                return false;
            }
            void* ctx_memory = malloc(blst_pairing_sizeof());
            if (!ctx_memory) {
                return false;
            }

            blst_pairing* ctx = static_cast<blst_pairing*>(ctx_memory);
            blst_pairing_init(ctx, true, reinterpret_cast<const uint8_t*>(DST),
                              strlen(DST));

            for (size_t i = 0; i < messages.size(); ++i) {
                auto pk_bytes = hex_to_bytes(publicKeysHex[i]);
                if (pk_bytes.size() != G1_COMPRESSED_SIZE) {
                    free(ctx_memory);
                    return false;
                }

                blst_p1_affine pk_affine;
                if (blst_p1_uncompress(&pk_affine, pk_bytes.data()) !=
                    BLST_SUCCESS) {
                    free(ctx_memory);
                    return false;
                }

                if (!blst_p1_affine_in_g1(&pk_affine)) {
                    free(ctx_memory);
                    return false;
                }

                BLST_ERROR err = blst_pairing_chk_n_aggr_pk_in_g1(
                    ctx, &pk_affine, true, nullptr, false,
                    reinterpret_cast<const uint8_t*>(messages[i].data()),
                    messages[i].size());

                if (err != BLST_SUCCESS) {
                    free(ctx_memory);
                    return false;
                }
            }
            blst_pairing_commit(ctx);
            blst_fp12 gtsig;
            blst_aggregated_in_g2(&gtsig, &agg_sig_affine);

            bool result = blst_pairing_finalverify(ctx, &gtsig);
            free(ctx_memory);
            return result;
        } catch (...) {
            return false;
        }
    }

} // namespace esl::crypto
