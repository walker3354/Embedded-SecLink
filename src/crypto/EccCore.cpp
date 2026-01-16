#include "esl/crypto/EccCore.hpp"

#include <iomanip>
#include <iostream>
#include <sstream>

#include "AesCore.hpp"
#include "esl/utils/Random.hpp"
#include "picosha2.h"
#include "uECC.h"

using namespace std;
using namespace picosha2;
namespace esl::crypto {

    int rng_function(uint8_t* dest, unsigned size) {
        try {
            static esl::utils::Random rng(0, 255);
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

    string byte_to_hex(const uint8_t* data, size_t len) {
        stringstream ss;
        ss << hex << setfill('0');
        for (size_t i = 0; i < len; ++i) {
            ss << setw(2) << static_cast<int>(data[i]);
        }
        return ss.str();
    }
    struct EccCore::Impl {
            uint8_t private_key[32];
            uint8_t public_key[64];
            uint8_t compressed_public_key[33];
            const struct uECC_Curve_t* curve = uECC_secp256r1();

            Impl() { uECC_set_rng(&rng_function); } // define rng
    };

    EccCore::EccCore(bool dev_mode) : m_impl(make_unique<Impl>()) {
        this->dev_mode = dev_mode;
        this->generate_keys();
    }

    EccCore::~EccCore() = default;

    EccCore::EccCore(EccCore&&) noexcept = default;
    EccCore& EccCore::operator=(EccCore&&) noexcept = default;

    void EccCore::generate_keys() {
        int result = uECC_make_key(m_impl->public_key, m_impl->private_key,
                                   m_impl->curve);
        uECC_compress(m_impl->public_key, m_impl->compressed_public_key,
                      m_impl->curve);
        if (result == 0) {
            throw runtime_error("Ecc generate keys failed");
        }
    }

    vector<uint8_t> EccCore::get_public_key() const {
        return vector<uint8_t>(m_impl->public_key,
                               m_impl->public_key + sizeof(m_impl->public_key));
    }

    vector<uint8_t> EccCore::get_private_key() const {
        if (this->dev_mode == true) {
            return vector<uint8_t>(
                m_impl->private_key,
                m_impl->private_key + sizeof(m_impl->private_key));
        }
        cout << "Dev mode off" << endl;
        return vector<uint8_t>();
    }

    vector<uint8_t> EccCore::get_compressed_public_key() const {
        return vector<uint8_t>(m_impl->compressed_public_key,
                               m_impl->compressed_public_key +
                                   sizeof(m_impl->compressed_public_key));
    }

    string EccCore::get_public_key_Hex() const {
        return byte_to_hex(m_impl->public_key,
                           sizeof(m_impl->public_key) / sizeof(uint8_t));
    }

    string EccCore::get_private_key_Hex() const {
        return byte_to_hex(m_impl->private_key,
                           sizeof(m_impl->private_key) / sizeof(uint8_t));
    }

    string EccCore::get_compressed_public_key_Hex() const {
        return byte_to_hex(
            m_impl->compressed_public_key,
            sizeof(m_impl->compressed_public_key) / sizeof(uint8_t));
    }

    vector<uint8_t> EccCore::ECDSA(const string& message) const {
        vector<uint8_t> hashed_message(k_digest_size);
        vector<uint8_t> signature(64);
        hash256(message.begin(), message.end(), hashed_message.begin(),
                hashed_message.end());
        int result = uECC_sign(m_impl->private_key, hashed_message.data(),
                               static_cast<unsigned>(hashed_message.size()),
                               signature.data(), m_impl->curve);
        if (result == 0) throw runtime_error("ECC: ECDSA signing failed");
        return signature;
    }

    bool EccCore::verify_signature(const vector<uint8_t>& public_key,
                                   const string& message,
                                   const vector<uint8_t>& signature) {
        if (signature.size() != 64) return false;
        vector<uint8_t> temp_pk = public_key;
        const struct uECC_Curve_t* curve = uECC_secp256r1();
        if (public_key.size() == 33) {
            temp_pk.resize(64);
            uECC_decompress(public_key.data(), temp_pk.data(), curve);
        } else if (public_key.size() != 64)
            return false;

        vector<uint8_t> hash(k_digest_size);
        hash256(message.begin(), message.end(), hash.begin(), hash.end());

        int result = uECC_verify(public_key.data(), hash.data(),
                                 static_cast<unsigned>(hash.size()),
                                 signature.data(), curve);
        return (result == 1);
    }

    vector<uint8_t> EccCore::ECDH(
        const vector<uint8_t>& peer_public_key) const {
        vector<uint8_t> raw_peer_key = peer_public_key;
        if (peer_public_key.size() == 33) {
            raw_peer_key.resize(64);
            uECC_decompress(peer_public_key.data(), raw_peer_key.data(),
                            m_impl->curve);
        } else if (peer_public_key.size() != 64)
            throw invalid_argument("ECDH: Invalid peer public key size");
        vector<uint8_t> session_key(EccCore::session_key_size);
        int result =
            uECC_shared_secret(raw_peer_key.data(), m_impl->private_key,
                               session_key.data(), m_impl->curve);
        if (result == 0) throw runtime_error("ECDH failed");
        return session_key; // 32 bytes
    }

    vector<uint8_t> EccCore::symmetric_encrypt(
        const vector<uint8_t>& session_key, const string& message) {
        if (session_key.size() != EccCore::session_key_size) {
            throw runtime_error("ECC: Session key length must be 32 bytes");
        }

        vector<uint8_t> temp_key(k_digest_size);
        hash256(session_key.begin(), session_key.end(), temp_key.begin(),
                temp_key.end());
        vector<uint8_t> aes_key(temp_key.begin(),
                                temp_key.begin() + AesCore::KEY_SIZE);

        uint8_t temp_rng[AesCore::IV_SIZE];

        if (rng_function(temp_rng, AesCore::IV_SIZE) != 1) {
            throw runtime_error("ECC: RNG generation failed");
        }
        vector<uint8_t> iv(temp_rng, temp_rng + AesCore::IV_SIZE);
        vector<uint8_t> plaintext(message.begin(), message.end());

        vector<uint8_t> ciphertext =
            AesCore::encrypt_cbc(plaintext, aes_key, iv);
        vector<uint8_t> result;
        result.reserve(iv.size() + ciphertext.size());
        result.insert(result.end(), iv.begin(), iv.end());
        result.insert(result.end(), ciphertext.begin(), ciphertext.end());

        return result;
    }

    string EccCore::symmetric_decrypt(
        const vector<uint8_t>& session_key,
        const vector<uint8_t>& encrypted_data) const {
        if (session_key.size() != EccCore::session_key_size) {
            throw runtime_error("ECC: Session key length must be 32 bytes");
        }
        if (encrypted_data.size() < AesCore::IV_SIZE + AesCore::BLOCK_SIZE) {
            throw runtime_error("ECC: Encrypted data too short");
        }
        vector<uint8_t> temp_key(k_digest_size);
        hash256(session_key.begin(), session_key.end(), temp_key.begin(),
                temp_key.end());
        vector<uint8_t> aes_key(temp_key.begin(),
                                temp_key.begin() + AesCore::KEY_SIZE);
        vector<uint8_t> iv(encrypted_data.begin(),
                           encrypted_data.begin() + AesCore::IV_SIZE);
        vector<uint8_t> ciphertext(encrypted_data.begin() + AesCore::IV_SIZE,
                                   encrypted_data.end());
        vector<uint8_t> plaintext =
            AesCore::decrypt_cbc(ciphertext, aes_key, iv);

        return string(plaintext.begin(), plaintext.end());
    }

    vector<uint8_t> EccCore::asymmetric_encrypt(
        const vector<uint8_t>& peer_public_key, const string& message) const {
        EccCore ephemeral_key(true);
        vector<uint8_t> session_key = ephemeral_key.ECDH(peer_public_key);
        vector<uint8_t> encrypted_payload =
            ephemeral_key.symmetric_encrypt(session_key, message);

        vector<uint8_t> result;
        vector<uint8_t> eph_pub_key = ephemeral_key.get_compressed_public_key();
        result.reserve(eph_pub_key.size() + encrypted_payload.size());
        result.insert(result.end(), eph_pub_key.begin(), eph_pub_key.end());
        result.insert(result.end(), encrypted_payload.begin(),
                      encrypted_payload.end());

        return result;
    }

    string EccCore::asymmetric_decrypt(
        const vector<uint8_t>& encrypted_package) const {
        size_t min_len = EccCore::compressed_pk_size + AesCore::IV_SIZE +
                         AesCore::BLOCK_SIZE;
        if (encrypted_package.size() < min_len) {
            throw runtime_error("ECC: Asymmetric encrypted package too short");
        }
        vector<uint8_t> eph_pub_key(
            encrypted_package.begin(),
            encrypted_package.begin() + EccCore::compressed_pk_size);
        vector<uint8_t> encrypted_payload(
            encrypted_package.begin() + EccCore::compressed_pk_size,
            encrypted_package.end());
        vector<uint8_t> session_key = this->ECDH(eph_pub_key);
        return this->symmetric_decrypt(session_key, encrypted_payload);
    }

} // namespace esl::crypto