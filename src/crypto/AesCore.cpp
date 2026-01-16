#include "esl/crypto/AesCore.hpp"

#include <stdexcept>

#include "aes.hpp"

using namespace std;

namespace {
    void apply_padding(vector<uint8_t>& buffer) {
        size_t padding_len = esl::crypto::AesCore::BLOCK_SIZE -
                             (buffer.size() % esl::crypto::AesCore::BLOCK_SIZE);
        for (size_t i = 0; i < padding_len; i++) {
            buffer.push_back(static_cast<uint8_t>(padding_len));
        }
    }

    void remove_padding(vector<uint8_t>& buffer) {
        if (buffer.empty()) {
            throw runtime_error("AES: Decrypt failed (empty buffer)");
        }
        size_t padding_len = static_cast<size_t>(buffer.back());
        if (padding_len == 0 ||
            padding_len > esl::crypto::AesCore::BLOCK_SIZE ||
            padding_len > buffer.size()) {
            throw runtime_error("AES: Decrypt failed (invalid padding)");
        }
        for (size_t i = 0; i < padding_len; i++) {
            if (buffer[buffer.size() - 1 - i] != padding_len)
                throw runtime_error(
                    "AES: Decrypt padding failed (content mismatch)");
        }
        buffer.resize(buffer.size() - padding_len);
    }
} // namespace

namespace esl::crypto {

    vector<uint8_t> AesCore::encrypt_cbc(const vector<uint8_t>& plaintext,
                                         const vector<uint8_t>& key,
                                         const vector<uint8_t>& iv) {
        if (key.size() != KEY_SIZE || iv.size() != IV_SIZE) {
            throw invalid_argument(
                "AES: Invalid key or IV size (must be 16 bytes");
        }
        vector<uint8_t> buffer = plaintext;
        apply_padding(buffer);

        struct AES_ctx ctx;
        vector<uint8_t> working_iv = iv;
        AES_init_ctx_iv(&ctx, key.data(), working_iv.data());
        AES_CBC_encrypt_buffer(&ctx, buffer.data(), buffer.size());
        return buffer;
    }

    vector<uint8_t> AesCore::decrypt_cbc(const vector<uint8_t>& ciphertext,
                                         const vector<uint8_t>& key,
                                         const vector<uint8_t>& iv) {
        if (key.size() != KEY_SIZE || iv.size() != IV_SIZE) {
            throw invalid_argument("AES: Invalid key or IV size");
        }
        if (ciphertext.size() == 0 || (ciphertext.size() % BLOCK_SIZE != 0)) {
            throw invalid_argument(
                "AES: Ciphertext size must be multiple of 16");
        }

        vector<uint8_t> buffer = ciphertext;
        struct AES_ctx ctx;
        vector<uint8_t> working_iv = iv;
        AES_init_ctx_iv(&ctx, key.data(), working_iv.data());

        AES_CBC_decrypt_buffer(&ctx, buffer.data(), buffer.size());
        remove_padding(buffer);
        return buffer;
    }
} // namespace esl::crypto