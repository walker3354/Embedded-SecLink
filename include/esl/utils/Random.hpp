#pragma once
#include <random>

namespace esl::utils {
    class Random {
        private:
            std::mt19937 random_generator;
            std::uniform_int_distribution<> distrib;

        public:
            Random(int min, int max);

            void set_random_range(int min, int max);
            int get_random_int();
            static int getIntGlobal(int min, int max);

            ~Random();
    };

}; // namespace esl::utils