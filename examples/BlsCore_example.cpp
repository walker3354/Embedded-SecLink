#include <iostream>
#include <random>
#include <string>

#include "esl/crypto/BlsCore.hpp"
#include "esl/utils/Random.hpp"

using namespace std;
using namespace esl;

bool test_bls_aggregate_sign();
bool test_bls_fast_aggregate_sign();

int main() {
    string test_message = "hi";
    try {
        crypto::BlsCore bls_component(true);
        cout << "pk: " << bls_component.get_public_keyHex() << endl;
        cout << "sk: " << bls_component.get_secret_keyHex() << endl;

        bool sign_result = bls_component.bls_verify(
            test_message, bls_component.bls_sign(test_message),
            bls_component.get_public_keyHex());
        cout << "Bls sign test result: "
             << (sign_result == 1 ? "Pass" : "Error") << endl;

        bool pop_result = bls_component.verify_pop_proof(
            bls_component.get_public_keyHex(), bls_component.get_pop_proof());
        cout << "Pop proof test result: "
             << (pop_result == 1 ? "Pass" : "Error") << endl;

        cout << "Bls aggregate sign(distinct) test result: "
             << (test_bls_aggregate_sign() == true ? "Pass" : "Error") << endl;

        cout << "Bls aggregate sign(fast) test result: "
             << (test_bls_fast_aggregate_sign() == true ? "Pass" : "Error")
             << endl;

    } catch (const std::exception& e) {
        cout << "error occur: " << e.what() << endl;
    }
    return 0;
}

bool test_bls_aggregate_sign() {
    vector<string> pk_vector;
    vector<string> sign_vector;
    vector<string> message_vector;
    for (int i = 0; i < 3; i++) {
        crypto::BlsCore bls(true);
        pk_vector.push_back(bls.get_public_keyHex());
        string message = to_string(utils::Random::getIntGlobal(0, 255));
        message_vector.push_back(message);
        sign_vector.push_back(bls.bls_sign(message));
    }
    string agg_sign = crypto::BlsCore::aggregate_signatures(sign_vector);
    return crypto::BlsCore::verify_aggregate_signature_distinct_messages(
        message_vector, pk_vector, agg_sign);
}

bool test_bls_fast_aggregate_sign() {
    string message = to_string(utils::Random::getIntGlobal(0, 100));
    vector<string> pk_vector;
    vector<string> sign_vector;
    for (int i = 0; i < 100; i++) {
        crypto::BlsCore bls(true);
        pk_vector.push_back(bls.get_public_keyHex());
        sign_vector.push_back(bls.bls_sign(message));
    }
    string agg_sign = crypto::BlsCore::aggregate_signatures(sign_vector);
    string agg_pk = crypto::BlsCore::aggregate_public_keys(pk_vector);
    bool vector_result = crypto::BlsCore::verify_fast_aggregate_verify(
        message, agg_sign, pk_vector);
    bool agg_result = crypto::BlsCore::verify_fast_aggregate_verify(
        message, agg_sign, agg_pk);
    return (vector_result & agg_result);
}
