#pragma once
#include <chrono>
#include <utility>

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

            template <typename Func, typename... Args>
            static double measure_execute_ms(Func&& func, Args&&... args) {
                Stopwatch sw(true);
                std::forward<Func>(func)(std::forward<Args>(args)...);
                return sw.get_once_elapsed_ms();
            }

            template <typename Func, typename... Args>
            static double measure_execute_us(Func&& func, Args&&... args) {
                Stopwatch sw(true);
                std::forward<Func>(func)(std::forward<Args>(args)...);
                return sw.get_once_elapsed_us();
            }
    };
} // namespace esl::utils