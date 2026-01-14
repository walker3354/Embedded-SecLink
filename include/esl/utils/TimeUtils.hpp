#pragma once

#include <chrono>
#include <string>

namespace esl::utils {
    class TimeUtils {
        private:
        public:
            TimeUtils();
            ~TimeUtils();
            static std::chrono::milliseconds get_current_time_ms();
            static std::chrono::seconds get_current_time_s();

            static std::string format_Timestamp_ms(
                std::chrono::milliseconds ms);
            static std::string format_Timestamp_s(std::chrono::seconds sec);

            bool check_timestamp_fresh_ms(std::chrono::milliseconds ms,
                                          time_t tolerance_ms = 1000);
            bool check_timestamp_fresh_s(std::chrono::seconds sec,
                                         time_t tolerance_s = 5);
    };
} // namespace esl::utils
