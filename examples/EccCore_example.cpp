// examples/EccCore_example.cpp
#include <cassert>
#include <iomanip>
#include <iostream>
#include <string>
#include <vector>

#include "esl/crypto/EccCore.hpp"
#include "esl/utils/Random.hpp"

using namespace std;
using namespace esl;

void print_hex(const string& label, const vector<uint8_t>& data) {
    cout << label << " (" << data.size() << " bytes): ";
    for (size_t i = 0; i < data.size(); ++i) {
        cout << hex << uppercase << setw(2) << setfill('0') << (int)data[i];
    }
    cout << dec << endl;
}

bool test_ecdsa_sign_verify();
bool test_ecdh_key_exchange();
bool test_symmetric_crypto();
bool test_asymmetric_hybrid_crypto();

int main() {
    cout << "=== Starting EccCore Functional Tests ===\n" << endl;

    try {
        cout << "[1] ECDSA Signature Test: "
             << (test_ecdsa_sign_verify() ? "PASS" : "FAIL") << endl;

        cout << "[2] ECDH Key Exchange Test: "
             << (test_ecdh_key_exchange() ? "PASS" : "FAIL") << endl;

        cout << "[3] Symmetric Encryption Test: "
             << (test_symmetric_crypto() ? "PASS" : "FAIL") << endl;

        cout << "[4] Asymmetric Hybrid Encryption Test: "
             << (test_asymmetric_hybrid_crypto() ? "PASS" : "FAIL") << endl;

    } catch (const exception& e) {
        cerr << "Exception occurred: " << e.what() << endl;
        return 1;
    }

    cout << "\n=== All Tests Finished ===" << endl;
    return 0;
}

bool test_ecdsa_sign_verify() {
    crypto::EccCore ecc(true); // dev_mode = true
    string message = "Hello ESL!";
    vector<uint8_t> signature = ecc.ECDSA(message);
    bool valid = crypto::EccCore::verify_signature(ecc.get_public_key(),
                                                   message, signature);
    bool invalid = crypto::EccCore::verify_signature(
        ecc.get_public_key(), "Wrong Message", signature);

    return valid && !invalid;
}

bool test_ecdh_key_exchange() {
    crypto::EccCore alice(true);
    crypto::EccCore bob(true);
    vector<uint8_t> alice_secret = alice.ECDH(bob.get_public_key());
    vector<uint8_t> bob_secret = bob.ECDH(alice.get_public_key());
    if (alice_secret.size() != 32 || bob_secret.size() != 32) return false;
    return alice_secret == bob_secret;
}

bool test_symmetric_crypto() {
    crypto::EccCore ecc(true);
    string original_msg = "Sensitive Data Payload";
    vector<uint8_t> session_key(32);
    for (int i = 0; i < 32; i++) session_key[i] = (uint8_t)i;
    vector<uint8_t> ciphertext =
        ecc.symmetric_encrypt(session_key, original_msg);
    string decrypted_msg = ecc.symmetric_decrypt(session_key, ciphertext);
    return original_msg == decrypted_msg;
}

bool test_asymmetric_hybrid_crypto() {
    crypto::EccCore alice(true); // Sender
    crypto::EccCore bob(true);   // Receiver
    string message = "Hybrid Encrypted Message for Bob only.";
    vector<uint8_t> encrypted_package =
        alice.asymmetric_encrypt(bob.get_public_key(), message);
    if (encrypted_package.size() <= 33 + 16) return false;
    string decrypted_msg = bob.asymmetric_decrypt(encrypted_package);
    return message == decrypted_msg;
}
