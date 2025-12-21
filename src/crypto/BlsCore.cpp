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
        try {
            initPairing(mcl::BLS12_381);
        } catch (const exception& e) {
            throw runtime_error(std::string("mcl init failed: ") + e.what());
        } catch (...) {
            throw runtime_error("mcl init failed with unknown error");
        }
    }

    void BlsCore::generate_keys() {
        keys->secretKey.setByCSPRNG(); // or .setRand()
        G1 Q;
        mapToG1(Q, 1);
        G1::mul(keys->publicKey, Q, keys->secretKey);
    }

    string BlsCore::get_public_keyHex() const {
        return this->keys->publicKey.getStr(10);
    }

    string BlsCore::get_secret_keyHex() const {
        if (this->dev_mode == true) {
            return this->keys->secretKey.getStr(10);
        }
        return "";
    }

    string BlsCore::bls_sign(const std::string& message) const {
        G2 hash_point;
        hashAndMapToG2(hash_point, message);
        G2 signature;
        G2::mul(signature, hash_point, this->keys->secretKey);
        return signature.getStr(10);
    }

    bool BlsCore::bls_verify(const std::string& message,
                             const std::string& signatureHex,
                             const std::string& publicKeyHex) {
        try {
            G2 pk;
            G1 sig;
            G1 H;
            G2 Q;
            GT e1, e2;
            pk.setStr(publicKeyHex, 16);
            sig.setStr(signatureHex, 16);
            hashAndMapToG1(H, message.c_str(), message.size());
            mapToG2(Q, 1);
            pairing(e1, H, pk);
            pairing(e2, sig, Q);
            return e1 == e2;
        } catch (...) {
            return false;
        }
    }
} // namespace esl::crypto
