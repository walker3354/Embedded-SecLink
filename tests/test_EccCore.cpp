#include <gtest/gtest.h>

#include <stdexcept>
#include <string>
#include <vector>

#include "esl/crypto/EccCore.hpp"

using namespace std;
using namespace esl::crypto;

// Test Fixture for EccCore
class EccCoreTest : public ::testing::Test {
    protected:
        EccCore alice;
        EccCore bob;
        EccCoreTest() : alice(true), bob(true) {}
        void SetUp() override {}
};

TEST_F(EccCoreTest, KeyGenerationProperties) {
    EXPECT_EQ(alice.get_private_key().size(), 32);
    EXPECT_EQ(alice.get_public_key().size(), 64);
    EXPECT_EQ(alice.get_compressed_public_key().size(), 33);
    EXPECT_EQ(alice.get_private_key_Hex().length(), 64);
    EXPECT_EQ(alice.get_public_key_Hex().length(), 128);
}

TEST_F(EccCoreTest, EcdsaSignAndVerify) {
    string message = "Hello V2X World";
    auto signature = alice.ECDSA(message);
    EXPECT_EQ(signature.size(), 64);
    bool valid =
        EccCore::verify_signature(alice.get_public_key(), message, signature);
    EXPECT_TRUE(valid)
        << "Signature verification failed with correct key and message";

    bool tampered_msg = EccCore::verify_signature(alice.get_public_key(),
                                                  "Hacked Message", signature);
    EXPECT_FALSE(tampered_msg) << "Signature should fail with modified message";
    bool wrong_key =
        EccCore::verify_signature(bob.get_public_key(), message, signature);
    EXPECT_FALSE(wrong_key) << "Signature should fail with wrong public key";
}

TEST_F(EccCoreTest, EcdhKeyExchange) {
    auto alice_shared = alice.ECDH(bob.get_public_key());
    auto bob_shared = bob.ECDH(alice.get_public_key());
    EXPECT_EQ(alice_shared.size(), 32);
    EXPECT_EQ(alice_shared, bob_shared) << "ECDH shared secrets mismatch";
    EccCore charlie(true);
    auto charlie_shared = charlie.ECDH(alice.get_public_key());
    EXPECT_NE(alice_shared, charlie_shared)
        << "Shared secret should differ for different pairs";
}

TEST_F(EccCoreTest, SymmetricEncryption) {
    string plaintext = "Confidential Data";
    auto session_key = alice.ECDH(bob.get_public_key());
    auto ciphertext = alice.symmetric_encrypt(session_key, plaintext);
    EXPECT_FALSE(ciphertext.empty());
    auto decrypted = alice.symmetric_decrypt(session_key, ciphertext);
    EXPECT_EQ(decrypted, plaintext) << "Decryption failed to restore plaintext";
    EccCore charlie(true);
    auto wrong_key = charlie.ECDH(bob.get_public_key()); // Charlie-Bob key
    EXPECT_THROW(
        { alice.symmetric_decrypt(wrong_key, ciphertext); }, std::exception);
}

TEST_F(EccCoreTest, AsymmetricHybridEncryption) {
    string plaintext = "Hybrid Secured Message";
    auto encrypted_package =
        alice.asymmetric_encrypt(bob.get_public_key(), plaintext);
    EXPECT_GE(encrypted_package.size(), 33 + 16 + 16);
    auto decrypted = bob.asymmetric_decrypt(encrypted_package);
    EXPECT_EQ(decrypted, plaintext);
    EccCore charlie(true);
    EXPECT_THROW(
        { charlie.asymmetric_decrypt(encrypted_package); }, std::exception);
}