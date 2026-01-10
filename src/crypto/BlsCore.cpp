#include "esl/crypto/BlsCore.hpp"

#include <mcl/bls12_381.hpp>
#include <stdexcept>
#include <string>

using namespace std;
using namespace mcl::bls12;

namespace esl::crypto {
    struct BlsCore::Impl {
            Fr secretKey;
            G1 publicKey;
    };

    BlsCore::BlsCore(bool dev_mode) : keys(new Impl()) {
        this->globalInit();
        this->generate_keys();
        this->dev_mode = dev_mode;
    }
    BlsCore::~BlsCore() = default;

    void BlsCore::globalInit() {
        static once_flag init_flag;
        call_once(init_flag, []() {
            try {
                initPairing(mcl::BLS12_381);

            } catch (const exception& e) {
                throw runtime_error(std::string("mcl init failed: ") +
                                    e.what());
            } catch (...) {
                throw runtime_error("mcl init failed with unknown error");
            }
        });
    }

    void BlsCore::generate_keys() {
        keys->secretKey.setByCSPRNG(); // or .setRand()
        G1 Q;
        mapToG1(Q, 1);
        G1::mul(keys->publicKey, Q, keys->secretKey);
    }

    string BlsCore::get_public_keyHex() const {
        string pk_str;
        keys->publicKey.getStr(pk_str, 16 | mcl::IoPrefix);
        return pk_str;
    }

    string BlsCore::get_secret_keyHex() const {
        if (this->dev_mode == true) {
            return this->keys->secretKey.getStr(16 | mcl::IoPrefix);
        }
        cout << "this operation not allow (dev mode lock!)" << endl;
        return "";
    }

    string BlsCore::bls_sign(const std::string& message) const {
        G2 hash_point;
        hashAndMapToG2(hash_point, message.c_str(), message.size());

        G2 signature;
        G2::mul(signature, hash_point, this->keys->secretKey);

        string str;
        signature.getStr(str, 16 | mcl::IoPrefix);
        return str;
    }

    bool BlsCore::bls_verify(const std::string& message,
                             const std::string& signatureHex,
                             const std::string& publicKeyHex) {
        try {
            G1 pk;
            G2 sig;
            G2 H;
            G1 Q;
            GT e1, e2;

            pk.setStr(publicKeyHex, 16 | mcl::IoPrefix);
            sig.setStr(signatureHex, 16 | mcl::IoPrefix);

            hashAndMapToG2(H, message.c_str(), message.size());
            mapToG1(Q, 1);

            pairing(e1, Q, sig);
            pairing(e2, pk, H);

            return e1 == e2;
        } catch (...) {
            return false;
        }
    }

    string BlsCore::get_pop_proof() const {
        return this->bls_sign(this->get_public_keyHex());
    }

    bool BlsCore::verify_pop_proof(const std::string& pubKeysHex,
                                   const string& pop_proof) const {
        return this->bls_verify(pubKeysHex, pop_proof, pubKeysHex);
    }

    string BlsCore::aggregate_public_keys(
        const std::vector<std::string>& pubKeysHex) {
        if (pubKeysHex.empty() == true) return "";

        G1 agg_pk;
        agg_pk.clear();
        for (const auto& hex : pubKeysHex) {
            G1 pk;
            pk.setStr(hex, 16 | mcl::IoPrefix);
            G1::add(agg_pk, agg_pk, pk);
        }
        return agg_pk.getStr(16 | mcl::IoPrefix);
    }

    string BlsCore::aggregate_signatures(
        const std::vector<std::string>& signatures) {
        if (signatures.empty()) return "";

        G2 aggSig;
        aggSig.clear();
        for (const auto& hex : signatures) {
            G2 sig;
            sig.setStr(hex, 16 | mcl::IoPrefix);
            G2::add(aggSig, aggSig, sig);
        }
        return aggSig.getStr(16 | mcl::IoPrefix);
    }

    bool BlsCore::verify_fast_aggregate_verify(
        const std::string& message, const std::string& aggSignatureHex,
        const std::string& aggPublicKeyHex) {
        return BlsCore::bls_verify(message, aggSignatureHex, aggPublicKeyHex);
    }

    bool BlsCore::verify_fast_aggregate_verify(
        const std::string& message, const std::string& aggSignatureHex,
        const std::vector<std::string>& publicKeysHex) {
        string agg_pk_hex = BlsCore::aggregate_public_keys(publicKeysHex);
        return BlsCore::bls_verify(message, aggSignatureHex, agg_pk_hex);
    }

    bool BlsCore::verify_aggregate_signature_distinct_messages(
        const vector<string>& messages, const vector<string>& publicKeysHex,
        const string& aggSignatureHex) {
        if (messages.empty() == true || publicKeysHex.empty() == true)
            return false;
        if (messages.size() != publicKeysHex.size()) return false;

        try {
            G2 aggSig;
            aggSig.setStr(aggSignatureHex, 16 | mcl::IoPrefix);

            G1 Q;
            mapToG1(Q, 1);

            GT lhs;
            pairing(lhs, Q, aggSig);

            GT rhs;
            rhs.setOne();

            for (size_t i = 0; i < messages.size(); i++) {
                G1 pk;
                pk.setStr(publicKeysHex[i], 16 | mcl::IoPrefix);
                G2 H;
                hashAndMapToG2(H, messages[i].c_str(), messages[i].size());
                GT e;
                pairing(e, pk, H);
                rhs *= e;
            }

            return lhs == rhs;
        } catch (...) {
            return false;
        }
    }
} // namespace esl::crypto
