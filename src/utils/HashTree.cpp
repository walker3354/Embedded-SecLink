#include "esl/utils/HashTree.hpp"

#include <algorithm>
#include <iomanip>
#include <sstream>
#include <stdexcept>

#include "picosha2.h"
using namespace std;

namespace esl::utils {
    HashTree::HashTree(const vector<string>& data_blocks) {
        if (data_blocks.empty()) {
            throw invalid_argument("HashTree: data blocks cannot be empty");
        }
        m_leaf_count = data_blocks.size();
        vector<Hash> leaves;
        leaves.reserve(m_leaf_count);
        for (const string& str : data_blocks) {
            leaves.push_back(hash_string(str));
        }
        m_tree_levels.push_back(leaves);
        build_tree();
    }

    HashTree::~HashTree() = default;

    HashTree::Hash HashTree::hash_data(const uint8_t* data, size_t size) {
        Hash hash(picosha2::k_digest_size);
        picosha2::hash256(data, data + size, hash.begin(), hash.end());
        return hash;
    }

    HashTree::Hash HashTree::hash_string(const string& data) {
        return hash_data(reinterpret_cast<const uint8_t*>(data.data()),
                         data.size());
    }

    string HashTree::hash_to_hex(const Hash& hash) {
        stringstream ss;
        ss << hex << setfill('0');
        for (uint8_t i : hash) {
            ss << setw(2) << static_cast<int>(i);
        }
        return ss.str();
    }

    HashTree::Hash HashTree::hash_pair(const Hash& left, const Hash& right) {
        vector<uint8_t> buffer;
        buffer.reserve(left.size() + right.size());
        buffer.insert(buffer.end(), left.begin(), left.end());
        buffer.insert(buffer.end(), right.begin(), right.end());
        return hash_data(buffer.data(), buffer.size());
    }

    void HashTree::build_tree() {
        while (m_tree_levels.back().size() > 1) {
            const vector<Hash>& current_level = m_tree_levels.back();
            vector<Hash> next_level;
            next_level.reserve((current_level.size() + 1) / 2);

            for (size_t i = 0; i < current_level.size(); i += 2) {
                if (i + 1 < current_level.size()) {
                    next_level.push_back(
                        hash_pair(current_level[i], current_level[i + 1]));
                } else {
                    next_level.push_back(
                        hash_pair(current_level[i], current_level[i]));
                }
            }
            m_tree_levels.push_back(next_level);
        }
    }

    HashTree::Hash HashTree::get_root_hash() const {
        if (m_tree_levels.empty() || m_tree_levels.back().empty()) {
            return {};
        }
        return m_tree_levels.back()[0];
    }

    string HashTree::get_root_hash_hex() const {
        return hash_to_hex(get_root_hash());
    }

    vector<HashTree::Hash> HashTree::get_merkle_proof(size_t leaf_index) const {
        if (leaf_index >= m_leaf_count) {
            throw std::out_of_range("HashTree: Leaf index out of range");
        }

        vector<Hash> proof;
        size_t index = leaf_index;
        for (size_t level = 0; level < m_tree_levels.size() - 1; ++level) {
            const vector<Hash>& current_level = m_tree_levels[level];
            bool is_right_child = (index % 2 == 1);
            size_t sibling_index = is_right_child ? index - 1 : index + 1;

            if (sibling_index < current_level.size()) {
                proof.push_back(current_level[sibling_index]);
            } else {
                proof.push_back(current_level[index]);
            }
            index /= 2;
        }
        return proof;
    }

    bool HashTree::verify_proof(const Hash& root, const Hash& leaf_hash,
                                size_t leaf_index, const vector<Hash>& proof) {
        Hash current_hash = leaf_hash;
        size_t index = leaf_index;
        for (const Hash& sibling_hash : proof) {
            if (index % 2 == 0) {
                current_hash = hash_pair(current_hash, sibling_hash);
            } else {
                current_hash = hash_pair(sibling_hash, current_hash);
            }
            index /= 2;
        }
        return (current_hash == root);
    }

} // namespace esl::utils