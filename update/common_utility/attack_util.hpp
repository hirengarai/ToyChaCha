/*
 * Filename: attack_util.hpp
 *
 * Cryptanalysis-attack helpers: parameter structs for sampling and for
 * differential / linear trail experiments.
 */

#pragma once

#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <iomanip>
#include <iostream>
#include <limits>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "core_types.hpp"
#include "report_util.hpp"

namespace attack_util
{
    // ---------- thread-safe sampling distribution ---------

    struct SamplingParams
    {
        std::size_t samples_per_thread_ = 0;
        std::size_t num_batches_        = 0;

        // Uses hardware_concurrency to leave 1 core free for the OS
        std::size_t max_num_threads_ = []()
        {
            unsigned hw = std::thread::hardware_concurrency();
            return hw > 1 ? hw - 1 : 1;
        }();

        /// Returns total samples per batch across all threads.
        std::size_t samples_per_batch() const
        {
            if (samples_per_thread_ == 0)
                return 0;
            constexpr std::size_t max_val = std::numeric_limits<std::size_t>::max();
            if (max_num_threads_ > max_val / samples_per_thread_)
                return max_val;
            return samples_per_thread_ * max_num_threads_;
        }

        /// Returns the absolute total samples for the entire run.
        std::size_t total_samples() const
        {
            const std::size_t batch = samples_per_batch();
            if (batch == 0 || num_batches_ == 0)
                return 0;
            constexpr std::size_t max_val = std::numeric_limits<std::size_t>::max();
            if (batch > max_val / num_batches_)
                return max_val;
            return batch * num_batches_;
        }
    };

    // ---------- running bias / correlation report ---------

    /// Accumulates per-batch signed sums and prints the running estimate:
    ///
    ///   # Samples     Correlation (~2^)        Batch time
    ///   ------------  -----------------------  ----------
    ///   2^{23.32}     0.002053 ~ 2^{-8.93}     130ms
    ///   2^{24.32}     0.002061 ~ 2^{-8.92}     129ms
    ///
    /// Each sample contributes +1 for agreement or -1 for disagreement.
    /// Correlation is the signed sum divided by the number of samples.
    /// The near-zero 1-sigma error is approximately 1/sqrt(samples).
    class BiasReporter
    {
        double        sum_     = 0.0;   // signed sum so far
        u64           samples_ = 0;
        std::ostream &os_;

        static constexpr int W_SAMPLES = 12, W_CORR = 23, W_TIME = 10;

    public:
        explicit BiasReporter(std::ostream &os = std::cout) : os_(os) {}

        void print_header()
        {
            os_ << std::left
                << std::setw(W_SAMPLES) << "# Samples"
                << "  " << std::setw(W_CORR) << "Correlation (~2^)"
                << "  " << std::setw(W_TIME) << "Batch time" << "\n"
                << std::string(W_SAMPLES, '-')
                << "  " << std::string(W_CORR, '-')
                << "  " << std::string(W_TIME, '-') << "\n";
        }

        /// Existing match-count interface: convert matches to a signed sum.
        void add_batch(u64 matches, u64 batch_samples, std::chrono::milliseconds duration)
        {
            add_signed_batch(static_cast<std::int64_t>(matches)
                                 - static_cast<std::int64_t>(batch_samples - matches),
                             batch_samples, duration);
        }

        /// Folds one signed sum in; duration is this batch's time.
        void add_signed_batch(std::int64_t sum, u64 batch_samples,
                              std::chrono::milliseconds duration)
        {
            sum_     += static_cast<double>(sum);
            samples_ += batch_samples;

            os_ << std::left
                << std::setw(W_SAMPLES) << report_util::fmt_log2(static_cast<double>(samples_))
                << "  " << std::setw(W_CORR) << report_util::fmt_correlation(correlation())
                << "  " << std::setw(W_TIME) << report_util::format_time_cell(duration)
                << "\n";
        }

        /// Closing block: the mean correlation and total samples used.
        void print_summary(std::size_t label_width = 25)
        {
            report_util::ParamTable(label_width, os_)
                .row("Mean correlation", report_util::fmt_correlation(correlation()))
                .row("Total samples used", report_util::fmt_log2(static_cast<double>(samples_)));
        }

        /// Mean of the +/-1 samples; 0 before any batch has been added.
        double correlation() const
        {
            if (samples_ == 0)
                return 0.0;
            return sum_ / static_cast<double>(samples_);
        }

        /// 1-sigma error on the current correlation estimate.
        double std_error() const
        {
            return samples_ ? 1.0 / std::sqrt(static_cast<double>(samples_))
                            : std::numeric_limits<double>::infinity();
        }

        u64 samples() const { return samples_; }
    };

    // ---------- attack boundary data ---------

    using BitPos = std::pair<u16, u16>;

    /// (-1)^(fwd_parity XOR bwd_parity): +1 for agreement, -1 otherwise.
    inline int parity_sign(u32 fwd_parity, u32 bwd_parity)
    {
        return fwd_parity == bwd_parity ? 1 : -1;
    }

    /// Parity of the selected bits in a difference pair; W may be scalar or SIMD.
    /// Callers validate that each word/bit position is inside the state.
    template <class W>
    inline W masked_parity(const W *x, const W *dx, const std::vector<BitPos> &mask)
    {
        W result{};
        for (const auto &[word, bit] : mask)
            result ^= ((x[word] ^ dx[word]) >> bit) & u32{1};
        return result;
    }

    struct AttackParams
    {
        double round_start_ = 0.0;
        double round_end_   = 0.0;

        // Coordinate-based bit positions for programmatic manipulation
        std::vector<BitPos> input_diff_bits_;
        std::vector<BitPos> output_diff_bits_;

        // String-based bit patterns for parsing from OCP/autoguess files
        std::string input_diff_str_;
        std::string output_diff_str_;

        std::vector<BitPos> output_mask_bits_;
        std::string         output_mask_str_; // e.g. "0x0000000002000000" for bit 25
    };
}
