#include "esl/utils/Random.hpp"

#include <stdexcept>

using namespace std;

namespace esl::utils {
    Random::Random(int min, int max) {
        random_device rd;
        this->random_generator.seed(rd());
        this->set_random_range(min, max);
    }
    Random::~Random() = default;

    void Random::set_random_range(int min, int max) {
        this->distrib = uniform_int_distribution<int>(min, max);
    }

    int Random::get_random_int() {
        return this->distrib(this->random_generator);
    }

    int Random::getIntGlobal(int min, int max) {
        thread_local mt19937 gen{std::random_device{}()};

        uniform_int_distribution<> distrib(min, max);
        return distrib(gen);
    }
} // namespace esl::utils
