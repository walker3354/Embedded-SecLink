#include "esl/utils/TimeUtils.hpp"

using namespace std;
using namespace chrono;

namespace esl::utils {
    TimeUtils::TimeUtils() = default;
    TimeUtils::~TimeUtils() = default;

    milliseconds TimeUtils::get_current_time_ms() {
        system_clock::time_point current_time = system_clock::now();
        system_clock::duration current_duration =
            current_time.time_since_epoch();
        return duration_cast<milliseconds>(current_duration);
    }
    seconds TimeUtils::get_current_time_s() {
        system_clock::time_point current_time = system_clock::now();
        system_clock::duration current_duration =
            current_time.time_since_epoch();
        return duration_cast<seconds>(current_duration);
    }

    string TimeUtils::format_Timestamp_ms(milliseconds ms) {}
    string TimeUtils::format_Timestamp_s(seconds sec) {}

    bool TimeUtils::check_timestamp_fresh_ms(milliseconds ms) {}
    bool TimeUtils::check_timestamp_fresh_s(seconds sec) {}
} // namespace esl::utils