#include "esl/utils/TimeUtils.hpp"

#include <iomanip>
#include <sstream>

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

    string TimeUtils::format_Timestamp_ms(milliseconds ms) {
        seconds sec = duration_cast<seconds>(ms);
        long long remaining_ms = ms.count() % 1000;
        time_t t = sec.count();
        tm tm_struct = *localtime(&t);
        stringstream ss;
        ss << put_time(&tm_struct, "%Y-%m-%d %H:%M:%S") << "." << setfill('0')
           << setw(3) << remaining_ms;
        return ss.str();
    }

    string TimeUtils::format_Timestamp_s(seconds sec) {
        time_t t = sec.count();
        tm tm_struct = *localtime(&t); // transfer time(s) to struct
        stringstream ss;
        ss << put_time(&tm_struct, "%Y-%m-%d %H:%M:%S");
        return ss.str();
    }

    bool TimeUtils::check_timestamp_fresh_ms(milliseconds ms,
                                             time_t tolerance_ms) {
        milliseconds current_t = TimeUtils::get_current_time_ms();
        if (current_t.count() < ms.count()) return false;
        milliseconds time_diff = current_t - ms;
        return (time_diff.count() <= tolerance_ms);
    }

    bool TimeUtils::check_timestamp_fresh_s(seconds sec, time_t tolerance_s) {
        seconds current_t = TimeUtils::get_current_time_s();
        if (current_t.count() < sec.count()) return false;
        milliseconds time_diff = current_t - sec;
        return (time_diff.count() <= tolerance_s);
    }
} // namespace esl::utils