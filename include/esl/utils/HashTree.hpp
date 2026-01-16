#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace esl::utils {
    class HashTree {
        public:
            using Hash = std::vector<uint8_t>;

            explicit HashTree(const std::vector<std::string>& data_blocks);
            ~HashTree();

            Hash get_root_hash() const;
            std::string get_root_hash_hex() const;

            std::vector<Hash> get_merkle_proof(size_t leaf_index) const;

            static bool verify_proof(const Hash& root, const Hash& leaf_hash,
                                     size_t leaf_index,
                                     const std::vector<Hash>& proof);

            static Hash hash_string(const std::string& data);

            static std::string hash_to_hex(const Hash& hash);

        private:
            std::vector<std::vector<Hash>> m_tree_levels; // leaf->...->root
            size_t m_leaf_count;
            void build_tree();
            static Hash hash_data(const uint8_t* data, size_t size);
            static Hash hash_pair(const Hash& left, const Hash& right);
    };
} // namespace esl::utils