#include <cassert>
#include <iomanip>
#include <iostream>
#include <string>
#include <vector>

#include "esl/utils/HashTree.hpp"

using namespace std;
using namespace esl::utils;

void print_hash(const string& label, const string& hex) {
    cout << left << setw(15) << label << ": " << hex.substr(0, 16) << "..."
         << endl;
}

int main() {
    cout << "=== Starting HashTree (Merkle Tree) Example ===\n" << endl;

    try {
        cout << "[1] Building Merkle Tree..." << endl;
        vector<string> vehicles = {"Vehicle_A_ID", "Vehicle_B_ID",
                                   "Vehicle_C_ID", "Vehicle_D_ID",
                                   "Vehicle_E_ID"};

        HashTree tree(vehicles);

        string root_hex = tree.get_root_hash_hex();
        auto root_bytes = tree.get_root_hash();

        print_hash("Merkle Root", root_hex);
        cout << "  Tree built with " << vehicles.size() << " leaves.\n" << endl;

        size_t target_index = 2;
        string target_data = vehicles[target_index];

        cout << "[2] Generating Proof for: " << target_data << " (Index "
             << target_index << ")" << endl;

        auto proof = tree.get_merkle_proof(target_index);

        cout << "  Proof path length: " << proof.size() << endl;
        for (size_t i = 0; i < proof.size(); ++i) {
            print_hash("  L" + to_string(i) + " Sibling",
                       HashTree::hash_to_hex(proof[i]));
        }
        cout << endl;

        cout << "[3] Verifying Proof..." << endl;

        auto leaf_hash = HashTree::hash_string(target_data);
        print_hash("  Leaf Hash", HashTree::hash_to_hex(leaf_hash));

        bool is_valid =
            HashTree::verify_proof(root_bytes, leaf_hash, target_index, proof);

        if (is_valid) {
            cout << "--> Verification SUCCESS: Data is in the tree." << endl;
        } else {
            cerr << "--> Verification FAILED!" << endl;
            return 1;
        }

        cout << "\n[4] Tamper Resistance Test..." << endl;

        string fake_data = "Vehicle_C_Fake";
        auto fake_hash = HashTree::hash_string(fake_data);

        bool tamper_result =
            HashTree::verify_proof(root_bytes, fake_hash, target_index, proof);

        if (!tamper_result) {
            cout
                << "--> Tamper Check PASSED: Modified data failed verification."
                << endl;
        } else {
            cerr << "--> Tamper Check FAILED: Fake data passed verification!"
                 << endl;
            return 1;
        }

    } catch (const exception& e) {
        cerr << "Error: " << e.what() << endl;
        return 1;
    }

    cout << "\n=== HashTree Example Finished ===" << endl;
    return 0;
}
