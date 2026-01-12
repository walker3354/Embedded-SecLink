#pragma once
#include <chrono>

namespace esl::utils {
    class Stopwatch {
        private:
            std::chrono::steady_clock::time_point m_start_time;
            bool m_is_running;

        public:
            Stopwatch(bool start_timing = false);
            ~Stopwatch();

            void once_start();
            void once_stop();
            void once_reset();

            double get_once_elapsed_ms();
            double get_once_elapsed_us();
    };
} // namespace esl::utils