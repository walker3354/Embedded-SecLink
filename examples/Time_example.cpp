// examples/Time_example.cpp
#include <chrono>
#include <iomanip>
#include <iostream>
#include <thread>

#include "esl/utils/Stopwatch.hpp"
#include "esl/utils/TimeUtils.hpp"

using namespace std;
using namespace esl::utils;

void test_TimeUtils();
void test_Stopwatch();
void test_Stopwatch_measure();

int main() {
    cout << "=== Starting Time & Utils Examples ===\n" << endl;

    try {
        test_TimeUtils();
        test_Stopwatch();
        test_Stopwatch_measure();
    } catch (const exception& e) {
        cerr << "Error: " << e.what() << endl;
        return 1;
    }

    cout << "\n=== All Time examples finished ===" << endl;
    return 0;
}

void test_TimeUtils() {
    cout << "--- [1] Testing TimeUtils ---" << endl;

    auto now_ms = TimeUtils::get_current_time_ms();
    auto now_s = TimeUtils::get_current_time_s();

    cout << "Current Timestamp (ms): " << now_ms.count() << endl;
    cout << "Current Timestamp (s) : " << now_s.count() << endl;

    // 2. 格式化時間戳記
    string formatted_ms = TimeUtils::format_Timestamp_ms(now_ms);
    string formatted_s = TimeUtils::format_Timestamp_s(now_s);

    cout << "Formatted (ms): " << formatted_ms << endl;
    cout << "Formatted (s) : " << formatted_s << endl;

    TimeUtils tu;
    bool is_fresh_ms = TimeUtils::check_timestamp_fresh_ms(now_ms, 2000);
    bool is_fresh_s = TimeUtils::check_timestamp_fresh_s(now_s, 5);

    cout << "Is current timestamp fresh (ms)? " << (is_fresh_ms ? "Yes" : "No")
         << endl;
    cout << "Is current timestamp fresh (s)?  " << (is_fresh_s ? "Yes" : "No")
         << endl;

    auto old_time = now_ms - chrono::milliseconds(3000);
    bool is_old_fresh = TimeUtils::check_timestamp_fresh_ms(old_time, 2000);
    cout << "Is 3-second-old timestamp fresh (tolerance 2s)? "
         << (is_old_fresh ? "Yes" : "No") << endl;

    cout << endl;
}

void test_Stopwatch() {
    cout << "--- [2] Testing Stopwatch ---" << endl;

    Stopwatch sw1;
    cout << "Starting manual stopwatch..." << endl;
    sw1.once_start();
    this_thread::sleep_for(chrono::milliseconds(100));
    sw1.once_stop();

    cout << "Elapsed (ms): " << fixed << setprecision(2)
         << sw1.get_once_elapsed_ms() << " ms" << endl;
    cout << "Elapsed (μs): " << fixed << setprecision(0)
         << sw1.get_once_elapsed_us() << " μs" << endl;

    cout << "\nAuto-start stopwatch for 50ms..." << endl;
    Stopwatch sw2(true);
    this_thread::sleep_for(chrono::milliseconds(50));

    cout << "Elapsed (running, no stop called): " << sw2.get_once_elapsed_ms()
         << " ms" << endl;

    sw2.once_reset();
    cout << "After reset, re-start for 30ms..." << endl;
    sw2.once_start();
    this_thread::sleep_for(chrono::milliseconds(30));
    cout << "Elapsed after reset: " << sw2.get_once_elapsed_ms() << " ms"
         << endl;

    cout << endl;
}

void test_Stopwatch_measure() {
    cout << "--- [3] Testing Stopwatch::measure_execute ---" << endl;

    auto heavy_work = [](int sleep_ms) {
        this_thread::sleep_for(chrono::milliseconds(sleep_ms));
        cout << "  Heavy work completed (slept " << sleep_ms << "ms)" << endl;
    };

    cout << "Measuring function execution time (ms)..." << endl;
    double elapsed_ms = Stopwatch::measure_execute_ms(heavy_work, 120);
    cout << "  Measured execution time: " << elapsed_ms << " ms\n" << endl;

    cout << "Measuring function execution time (μs)..." << endl;
    double elapsed_us = Stopwatch::measure_execute_us(heavy_work, 80);
    cout << "  Measured execution time: " << elapsed_us << " μs\n" << endl;
}
