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

uint16_t key_id_1 = 1;
uint16_t key_id_2 = 2;

// Helper: Print Hex
void print_hex(const string& label, const vector<uint8_t>& data) {
    cout << label << " (" << data.size() << " bytes): ";
    for (size_t i = 0; i < data.size(); ++i) {
        cout << hex << uppercase << setw(2) << setfill('0') << (int)data[i];
    }
    cout << dec << endl;
}

bool test_ecdsa_sign_verify_bytes();
bool test_ecdsa_sign_verify_hex();
bool test_ecdsa_verify_compressed_key();
bool test_ecdh_key_exchange_bytes();
bool test_ecdh_key_exchange_hex();
bool test_ecdh_compressed_key();
bool test_symmetric_crypto();
bool test_asymmetric_hybrid_crypto();

int main() {
    cout << "=== Starting EccCore Functional Tests ===\n" << endl;

    try {
        cout << "[1-A] ECDSA (Bytes) Test:         "
             << (test_ecdsa_sign_verify_bytes() ? "PASS" : "FAIL") << endl;

        cout << "[1-B] ECDSA (Hex) Test:           "
             << (test_ecdsa_sign_verify_hex() ? "PASS" : "FAIL") << endl;

        cout << "[1-C] ECDSA (Compressed) Test:    "
             << (test_ecdsa_verify_compressed_key() ? "PASS" : "FAIL") << endl;

        cout << "[2-A] ECDH (Bytes) Test:          "
             << (test_ecdh_key_exchange_bytes() ? "PASS" : "FAIL") << endl;

        cout << "[2-B] ECDH (Hex) Test:            "
             << (test_ecdh_key_exchange_hex() ? "PASS" : "FAIL") << endl;

        cout << "[2-C] ECDH (Compressed) Test:     "
             << (test_ecdh_compressed_key() ? "PASS" : "FAIL") << endl;

        cout << "[3]   Symmetric Encryption Test:  "
             << (test_symmetric_crypto() ? "PASS" : "FAIL") << endl;

        cout << "[4]   Hybrid Encryption Test:     "
             << (test_asymmetric_hybrid_crypto() ? "PASS" : "FAIL") << endl;

    } catch (const exception& e) {
        cerr << "\n[CRITICAL] Exception occurred: " << e.what() << endl;
        return 1;
    }

    cout << "\n=== All Tests Finished ===" << endl;
    return 0;
}

bool test_ecdsa_sign_verify_bytes() {
    crypto::EccCore ecc(key_id_1, true);
    string message = "Hello ESL (Bytes)!";
    vector<uint8_t> signature = ecc.ECDSA(message);

    bool valid = crypto::EccCore::verify_signature(ecc.get_public_key(),
                                                   message, signature);
    bool invalid = crypto::EccCore::verify_signature(
        ecc.get_public_key(), "Wrong Message", signature);
    return valid && !invalid;
}

bool test_ecdsa_sign_verify_hex() {
    crypto::EccCore ecc(key_id_1, true);
    string message = "Hello ESL (Hex)!";
    vector<uint8_t> signature = ecc.ECDSA(message);

    // 使用 Hex String 公鑰介面
    bool valid = crypto::EccCore::verify_signature(ecc.get_public_key_Hex(),
                                                   message, signature);

    return valid;
}

bool test_ecdsa_verify_compressed_key() {
    crypto::EccCore ecc(key_id_1, true);
    string message = "Compressed Key Test";
    vector<uint8_t> signature = ecc.ECDSA(message);

    bool valid_bytes = crypto::EccCore::verify_signature(
        ecc.get_compressed_public_key(), message, signature);

    bool valid_hex = crypto::EccCore::verify_signature(
        ecc.get_compressed_public_key_Hex(), message, signature);

    return valid_bytes && valid_hex;
}

bool test_ecdh_key_exchange_bytes() {
    crypto::EccCore alice(1, true);
    crypto::EccCore bob(2, true);

    vector<uint8_t> alice_secret = alice.ECDH(bob.get_public_key());
    vector<uint8_t> bob_secret = bob.ECDH(alice.get_public_key());

    if (alice_secret.size() != 32 || bob_secret.size() != 32) return false;
    return alice_secret == bob_secret;
}

bool test_ecdh_key_exchange_hex() {
    crypto::EccCore alice(1, true);
    crypto::EccCore bob(2, true);

    vector<uint8_t> alice_secret = alice.ECDH(bob.get_public_key_Hex());
    vector<uint8_t> bob_secret = bob.ECDH(alice.get_public_key_Hex());

    return alice_secret == bob_secret;
}

bool test_ecdh_compressed_key() {
    crypto::EccCore alice(1, true);
    crypto::EccCore bob(2, true);

    vector<uint8_t> s1 = alice.ECDH(bob.get_compressed_public_key());
    vector<uint8_t> s2 =
        bob.ECDH(alice.get_compressed_public_key_Hex()); // 混用 Hex 測試

    return s1 == s2;
}

bool test_symmetric_crypto() {
    crypto::EccCore ecc(key_id_1, true);
    string original_msg = "Sensitive Data Payload";

    vector<uint8_t> session_key(32);
    for (int i = 0; i < 32; i++) session_key[i] = (uint8_t)i;

    vector<uint8_t> ciphertext =
        ecc.symmetric_encrypt(session_key, original_msg);
    string decrypted_msg = ecc.symmetric_decrypt(session_key, ciphertext);

    return original_msg == decrypted_msg;
}

bool test_asymmetric_hybrid_crypto() {
    crypto::EccCore alice(key_id_1, true); // Sender
    crypto::EccCore bob(key_id_2, true);   // Receiver

    string message = "Hybrid Encrypted Message for Bob only.";

    vector<uint8_t> encrypted_package =
        alice.asymmetric_encrypt(bob.get_public_key_Hex(), message);

    if (encrypted_package.size() <= 33 + 16) return false;

    string decrypted_msg = bob.asymmetric_decrypt(encrypted_package);

    return message == decrypted_msg;
}
