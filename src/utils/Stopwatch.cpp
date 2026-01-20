#include "esl/utils/Stopwatch.hpp"

#include <iostream>

using namespace std;
using namespace chrono;
namespace esl::utils {
    Stopwatch::Stopwatch(bool start_timing) {
        this->m_is_running = false;
        if (start_timing == true) this->once_start();
    }

    Stopwatch::~Stopwatch() = default;

    void Stopwatch::once_start() {
        this->m_is_running = true;
        this->m_start_time = steady_clock::now();
    }

    void Stopwatch::once_stop() { this->m_is_running = false; }

    void Stopwatch::once_reset() { this->m_is_running = false; }

    double Stopwatch::get_once_elapsed_ms() {
        steady_clock::time_point current_time = steady_clock::now();
        duration<double, milli> elapsed = current_time - m_start_time;
        return elapsed.count();
    }

    double Stopwatch::get_once_elapsed_us() {
        steady_clock::time_point current_time = steady_clock::now();
        duration<double, std::micro> elapsed = current_time - m_start_time;
        return elapsed.count();
    }
} // namespace esl::utils