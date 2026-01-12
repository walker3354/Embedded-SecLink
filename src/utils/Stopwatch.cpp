#include "esl\utils\Stopwatch.hpp"

using namespace std;
namespace esl::utils {
    Stopwatch::Stopwatch(bool start_timing) {
        this->m_is_running = false;
        if (start_timing == true) this->once_start();
    }

    Stopwatch::~Stopwatch() = default;

    void Stopwatch::once_start() {}

    void Stopwatch::once_stop() {}

    void Stopwatch::once_reset() {}
} // namespace esl::utils