#include "esl/crypto/EccCore.hpp"

#include "esl/utils/Random.hpp"
#include "uECC.h"

using namespace std;

namespace esl::crypto {

    int rng_function(uint8_t* dest, unsigned size) {
        static esl::utils::Random rng(0, 255);
        try {
            for (unsigned i = 0; i < size; i++) {
                dest[i] = static_cast<uint8_t>(rng.get_random_int());
            }
            return 1;
        } catch (...) {
            throw runtime_error(
                "Ecc generate random failed with unknown error");
            return 0;
        }
    }

    struct EccCore::Impl {
            uint8_t private_key[32];
            uint8_t public_key[64];
            const struct uECC_Curve_t* curve = uECC_secp256r1();

            EccCore::Impl() { uECC_set_rng(&rng_function); } // define rng
    };

    EccCore::EccCore(bool dev_mode) : m_impl(make_unique<Impl>()) {
        this->generate_keys();
    }

    void EccCore::generate_keys() {
        int result = uECC_make_key(m_impl->public_key, m_impl->private_key,
                                   m_impl->curve);
        if (result == 0) {
            throw runtime_error("Ecc generate keys failed");
        }
    }

    vector<uint8_t> EccCore::get_public_key() const {
        return vector<uint8_t>(m_impl->public_key,
                               m_impl->public_key + sizeof(m_impl->public_key));
    }

    vector<uint8_t> EccCore::get_public_key() const {
        return vector<uint8_t>(
            m_impl->private_key,
            m_impl->private_key + sizeof(m_impl->private_key));
    }

    string EccCore::get_public_key_Hex() const {
        
    }
} // namespace esl::crypto