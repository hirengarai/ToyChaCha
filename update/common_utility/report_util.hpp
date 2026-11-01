/*
 * Filename: report_util.hpp
 *
 * Helpers for cipher design-check / experiment runs:
 *   - Section separator and state hex printer (formatting)
 *   - Wall+steady run timer and duration formatter (timing)
 *   - Compiler / C++ standard introspection (environment)
 *
 * One include gives a script everything it needs to produce a readable run
 * report from start to finish.
 */

#pragma once

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstddef>
#include <cstdio>
#include <iomanip>
#include <ios>
#include <iostream>
#include <limits>
#include <sstream>
#include <string>
#include <string_view>

namespace report_util
{
    // ---------- formatting ----------

    inline constexpr const char *SEP =
        ":=:=:=:=:=:=:=:=::=:=:=:=:=:=:=:=::=:=:=:=:=:=:=:=::=:=:=:=:=:=:=:=:\n";

    /// A labeled separator, e.g. "--[ Configuration ]----------------...".
    inline std::string section(std::string_view title, std::size_t width = 76)
    {
        std::string line = "--[ " + std::string(title) + " ]";
        if (line.size() < width) line.append(width - line.size(), '-');
        return line;
    }

    /// Hex-dump `count` words from `state` in rows of `cols_per_row`.
    /// Width is auto-derived from sizeof(T); cast widens to unsigned long long
    /// so u8 prints as a number rather than a character glyph.
    template <typename T>
    inline void print_state_hex(const T *state,
                                std::size_t count,
                                std::size_t cols_per_row,
                                const std::string &label = "")
    {
        if (!label.empty())
            std::cout << label << "\n";

        const std::ios::fmtflags saved_flags = std::cout.flags();
        const char saved_fill                = std::cout.fill('0');
        const int hex_width                  = sizeof(T) * 2;

        std::cout << std::hex << std::right;
        for (std::size_t i = 0; i < count; ++i)
        {
            std::cout << "0x" << std::setw(hex_width)
                      << static_cast<unsigned long long>(state[i]);
            const bool last_in_row  = ((i + 1) % cols_per_row == 0);
            const bool last_overall = (i + 1 == count);
            if (last_in_row || last_overall)
                std::cout << "\n";
            else
                std::cout << " ";
        }

        std::cout.flags(saved_flags);
        std::cout.fill(saved_fill);
    }

    /// Renders a count as "2^{x.xx}". Uses snprintf rather than stream
    /// manipulators so it cannot leak fixed/setprecision into later output.
    inline std::string fmt_log2(double count)
    {
        char buf[32];
        std::snprintf(buf, sizeof(buf), "2^{%.2f}", std::log2(count));
        return buf;
    }

    /// A signed correlation in decimal and base two, including zero.
    inline std::string fmt_correlation(double correlation)
    {
        const double power = correlation == 0.0 ? -std::numeric_limits<double>::infinity()
                                                 : std::log2(std::fabs(correlation));
        char text[64];
        std::snprintf(text, sizeof(text), "%.6f ~ %s2^{%.2f}",
                      correlation, correlation < 0.0 ? "-" : "", power);
        return text;
    }

    /// A probability with enough decimal places for small differential hits.
    inline std::string fmt_probability(double probability)
    {
        char text[80];
        std::snprintf(text, sizeof(text), "%.12f ~ %s", probability,
                      fmt_log2(probability).c_str());
        return text;
    }

    // ---------- parameter table ----------

    /// Prints the "label : value" block at the head of a run report, with the
    /// colons aligned. Values are streamed, so any operator<< type works and a
    /// row can be assembled from several parts:
    ///
    ///   report_util::ParamTable t;
    ///   t.row("Key size", 256, " bits")
    ///    .row("Total rounds", 7.0);
    ///
    ///   Key size                 : 256 bits
    ///   Total rounds             : 7
    class ParamTable
    {
        std::size_t   label_width_;
        std::ostream &os_;

    public:
        explicit ParamTable(std::size_t label_width = 25, std::ostream &os = std::cout)
            : label_width_(label_width), os_(os) {}

        template <typename... Ts>
        ParamTable &row(std::string_view label, const Ts &...parts)
        {
            os_ << std::left << std::setw(static_cast<int>(label_width_)) << label << ": ";
            (os_ << ... << parts);
            os_ << "\n";
            return *this;
        }
    };

    // ---------- duration formatting ----------

    /// Converts milliseconds into a readable h/m/s/ms string format.
    inline std::string format_duration(std::chrono::milliseconds duration)
    {
        long long total_ms = std::max(0LL, static_cast<long long>(duration.count()));

        if (total_ms < 1000)
            return std::to_string(total_ms) + "ms";

        long long hours = total_ms / 3600000;
        total_ms %= 3600000;
        long long minutes = total_ms / 60000;
        total_ms %= 60000;
        long long seconds = total_ms / 1000;
        long long millis  = total_ms % 1000;

        std::ostringstream oss;
        if (hours > 0)
            oss << hours << "h ";
        if (minutes > 0)
            oss << minutes << "m ";
        if (seconds > 0)
            oss << seconds << "s ";
        if (millis > 0)
            oss << millis << "ms";

        std::string result = oss.str();
        if (!result.empty() && result.back() == ' ')
            result.pop_back();
        return result;
    }

    /// Per-row timing for result tables: raw milliseconds while that is still
    /// readable, hh:mm:ss once a span is long enough that a millisecond count
    /// is not. The unit travels with the value, so the column header does not
    /// have to promise one.
    inline std::string format_time_cell(std::chrono::milliseconds duration,
                                        long long hms_threshold_ms = 10000)
    {
        const long long ms = std::max(0LL, static_cast<long long>(duration.count()));
        if (ms < hms_threshold_ms)
            return std::to_string(ms) + "ms";

        const long long total_s = ms / 1000;
        char buf[24];
        std::snprintf(buf, sizeof(buf), "%02lld:%02lld:%02lld",
                      total_s / 3600, (total_s / 60) % 60, total_s % 60);
        return buf;
    }

    // ---------- run timer ----------

    struct RunTimer
    {
        std::chrono::system_clock::time_point wall_start_{std::chrono::system_clock::now()};
        std::chrono::steady_clock::time_point prog_start_{std::chrono::steady_clock::now()};

        static std::tm local_time(std::time_t t)
        {
            std::tm tm{};
#ifdef _WIN32
            localtime_s(&tm, &t);
#else
            localtime_r(&t, &tm);
#endif
            return tm;
        }

        /// Formats a wall-clock timestamp for console reports or saved metadata.
        static std::string timestamp(std::chrono::system_clock::time_point time,
                                     const char *format = "%Y-%m-%d %H:%M:%S %z")
        {
            const auto tm = local_time(std::chrono::system_clock::to_time_t(time));
            std::ostringstream text;
            text << std::put_time(&tm, format);
            return text.str();
        }

        /// Prints the formatted start time to the provided stream.
        void print_start(const char *format = "%Y-%m-%d %H:%M:%S",
                         std::ostream &os   = std::cout) const
        {
            os << "///---///---///--- Commencing entropy hunt on: "
               << timestamp(wall_start_, format) << " ---///---///---///\n";
        }

        /// Returns the elapsed execution time in milliseconds.
        std::chrono::milliseconds elapsed() const
        {
            return std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - prog_start_);
        }

        /// Prints the formatted end time AND total elapsed duration to the provided stream.
        void print_end(const char *format = "%Y-%m-%d %H:%M:%S",
                       std::ostream &os   = std::cout) const
        {
            os << "///---///---///--- State space exhausted on: "
               << timestamp(std::chrono::system_clock::now(), format) << " ---///---///---///\n";
            os << "///---///---///--- Time lost to the cipher : "
               << format_duration(elapsed()) << " ---///---///---///\n";
        }
    };

    // ---------- compiler & C++ standard ----------

    /// Returns a string identifying the compiler and its version.
    inline std::string compiler_info()
    {
#if defined(_MSC_VER)
        return "MSVC " + std::to_string(_MSC_VER);
#elif defined(__VERSION__)
        return __VERSION__;
#else
        return "Unknown compiler";
#endif
    }

    /// Prints the compiler version and C++ standard to the provided stream.
    inline void print_environment(std::ostream &os = std::cout)
    {
        os << "Compiler: " << compiler_info() << "\n";

        std::string standard = "Unknown";
        if (__cplusplus == 201703L)
            standard = "C++17";
        else if (__cplusplus == 202002L)
            standard = "C++20";
        else if (__cplusplus == 202302L)
            standard = "C++23";

        os << "Standard: " << standard << "\n";
    }
}
