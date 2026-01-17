#include <gtest/gtest.h>

#include <stdexcept>
#include <string>
#include <vector>

#include "esl/utils/HashTree.hpp"

using namespace std;
using namespace esl::utils;

class HashTreeTest : public ::testing::Test {
    protected:
        HashTree::Hash get_leaf_hash(const string& s) {
            return HashTree::hash_string(s);
        }
};

TEST_F(HashTreeTest, EmptyDataThrowsException) {
    vector<string> empty_data;
    EXPECT_THROW({ HashTree tree(empty_data); }, std::invalid_argument);
}

TEST_F(HashTreeTest, SingleNodeRootCalculation) {
    vector<string> data = {"SingleNode"};
    HashTree tree(data);
    auto expected_root = get_leaf_hash("SingleNode");
    auto actual_root = tree.get_root_hash();
    EXPECT_EQ(actual_root, expected_root)
        << "Root hash should match leaf hash for single node tree";
}

TEST_F(HashTreeTest, VerifyProofForEvenNodes) {
    vector<string> data = {"A", "B", "C", "D"};
    HashTree tree(data);
    auto root = tree.get_root_hash();
    for (size_t i = 0; i < data.size(); ++i) {
        auto proof = tree.get_merkle_proof(i);
        auto leaf_hash = get_leaf_hash(data[i]);
        bool is_valid = HashTree::verify_proof(root, leaf_hash, i, proof);
        EXPECT_TRUE(is_valid)
            << "Proof verification failed for leaf index " << i;
    }
}

TEST_F(HashTreeTest, VerifyProofForOddNodes) {
    vector<string> data = {"A", "B", "C"};
    HashTree tree(data);
    auto root = tree.get_root_hash();
    size_t index = 2;
    auto proof = tree.get_merkle_proof(index);
    auto leaf_hash = get_leaf_hash(data[index]);
    EXPECT_TRUE(HashTree::verify_proof(root, leaf_hash, index, proof));
}

TEST_F(HashTreeTest, DetectTamperedData) {
    vector<string> data = {"Car1", "Car2", "Car3", "Car4"};
    HashTree tree(data);
    auto root = tree.get_root_hash();
    auto proof = tree.get_merkle_proof(0);
    auto fake_hash = get_leaf_hash("Car1_Fake");

    bool valid = HashTree::verify_proof(root, fake_hash, 0, proof);
    EXPECT_FALSE(valid) << "Should reject tampered data (Fake Hash)";
    auto real_hash = get_leaf_hash("Car1");

    valid = HashTree::verify_proof(root, real_hash, 1, proof);
    EXPECT_FALSE(valid) << "Should reject correct data with wrong index";
    auto tampered_proof = proof;
    if (!tampered_proof.empty()) {
        tampered_proof[0][0] ^= 0xFF; // Flip bits
        valid = HashTree::verify_proof(root, real_hash, 0, tampered_proof);
        EXPECT_FALSE(valid) << "Should reject tampered proof";
    }
}