#include <gtest/gtest.h>

#include <string>
#include <vector>

#include "esl/crypto/BlsCore.hpp"

using namespace std;
using namespace esl::crypto;

class BlsCoreTest : public ::testing::Test {
    protected:
        BlsCore alice;
        BlsCore bob;
        BlsCoreTest() : alice(true), bob(true) {}

        void SetUp() override {
            ASSERT_FALSE(alice.get_secret_keyHex().empty());
            ASSERT_FALSE(alice.get_public_keyHex().empty());
        }
};

TEST_F(BlsCoreTest, KeyGenerationProperties) {
    EXPECT_GT(alice.get_secret_keyHex().length(), 0);
    EXPECT_GT(alice.get_public_keyHex().length(), 0);

    EXPECT_NE(alice.get_secret_keyHex(), bob.get_secret_keyHex());
    EXPECT_NE(alice.get_public_keyHex(), bob.get_public_keyHex());
}

TEST_F(BlsCoreTest, SignAndVerify) {
    string message = "Critical V2X Alert";

    string signature = alice.bls_sign(message);
    EXPECT_FALSE(signature.empty());

    bool valid =
        BlsCore::bls_verify(message, signature, alice.get_public_keyHex());
    EXPECT_TRUE(valid) << "BLS verification failed with correct key";

    bool valid_wrong_key =
        BlsCore::bls_verify(message, signature, bob.get_public_keyHex());
    EXPECT_FALSE(valid_wrong_key) << "BLS verification passed with wrong key";

    bool valid_tampered = BlsCore::bls_verify("Hacked Content", signature,
                                              alice.get_public_keyHex());
    EXPECT_FALSE(valid_tampered)
        << "BLS verification passed with tampered message";
}

TEST_F(BlsCoreTest, ProofOfPossession) {
    string pop = alice.get_pop_proof();
    EXPECT_FALSE(pop.empty());
    bool valid = alice.verify_pop_proof(alice.get_public_keyHex(), pop);
    EXPECT_TRUE(valid) << "PoP verification failed";
    bool valid_wrong = bob.verify_pop_proof(bob.get_public_keyHex(), pop);
    EXPECT_FALSE(valid_wrong)
        << "PoP verification passed with wrong public key";
}

TEST_F(BlsCoreTest, FastAggregateVerify) {
    string message = "Consensus Message";

    string sig_alice = alice.bls_sign(message);
    string sig_bob = bob.bls_sign(message);
    vector<string> signatures = {sig_alice, sig_bob};
    string agg_signature = BlsCore::aggregate_signatures(signatures);
    EXPECT_FALSE(agg_signature.empty());
    vector<string> public_keys = {alice.get_public_keyHex(),
                                  bob.get_public_keyHex()};
    string agg_pub_key = BlsCore::aggregate_public_keys(public_keys);
    EXPECT_FALSE(agg_pub_key.empty());
    bool valid1 = BlsCore::verify_fast_aggregate_verify(message, agg_signature,
                                                        agg_pub_key);
    EXPECT_TRUE(valid1) << "Fast aggregate verification (agg PK) failed";
    bool valid2 = BlsCore::verify_fast_aggregate_verify(message, agg_signature,
                                                        public_keys);
    EXPECT_TRUE(valid2) << "Fast aggregate verification (PK list) failed";
}

TEST_F(BlsCoreTest, AggregateVerifyDistinctMessages) {
    string msg1 = "Alice says Hello";
    string msg2 = "Bob says Hi";
    string sig_alice = alice.bls_sign(msg1);
    string sig_bob = bob.bls_sign(msg2);
    vector<string> signatures = {sig_alice, sig_bob};
    string agg_signature = BlsCore::aggregate_signatures(signatures);
    vector<string> messages = {msg1, msg2};
    vector<string> public_keys = {alice.get_public_keyHex(),
                                  bob.get_public_keyHex()};
    bool valid = BlsCore::verify_aggregate_signature_distinct_messages(
        messages, public_keys, agg_signature);
    EXPECT_TRUE(valid) << "Distinct messages aggregation failed";
    vector<string> wrong_messages = {msg2, msg1}; // 順序顛倒
    bool valid_wrong = BlsCore::verify_aggregate_signature_distinct_messages(
        wrong_messages, public_keys, agg_signature);
    EXPECT_FALSE(valid_wrong) << "Should fail when message order mismatch";
}
