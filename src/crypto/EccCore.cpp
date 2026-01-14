#include "esl/crypto/EccCore.hpp"

#include "uECC.h"

using namespace std;

namespace esl::crypto {

    struct EccCore::Impl {
            uint8_t private_key[32];
            uint8_t public_key[64];
            const struct uECC_Curve_t* curve;
    };

    EccCore::EccCore(bool dev_mode) : m_impl(new (Impl)) {}
} // namespace esl::crypto