/*
 * ToyChaCha distinguisher search (multiple (ID, OD) attack, offline)
 * Hiren | NTU Singapore
 * Created: 2026 | Updated: 2026-10-24
 *
 * For every input difference in the IV words 12..15 and every output bit after DIST_ROUND
 * rounds, the forward correlation eps_d = Pr(Delta = 0) - Pr(Delta = 1). Also reports the
 * (ID, OD) pair of every stage and how their eps_d spread over keys (Section 5).
 *
 * run.py builds and runs it:  ./dist_search --seed S --samples N --out dist_search.json
 */
#include "../../toychacha.hpp"
#include "../../toy_util.hpp"
#include "../../common_utility/attack_util.hpp"
#include "../../common_utility/core_types.hpp"
#include "../../common_utility/report_util.hpp"
#include "../../common_utility/state_ops.hpp"
#include "../../common_utility/string_ops.hpp"
#include "control_panel.hpp" // written by run.py

#include <array>
#include <cmath>
#include <cstdint>
#include <iostream>
#include <vector>

// ---- Settings ------------------------------------------------

constexpr int ID_BITS = 32;  // every bit of the IV words 12..15
constexpr int OD_BITS = 128; // every bit of the state
constexpr int TOP = 20;      // strongest pairs to report

using Sums = std::array<std::int64_t, OD_BITS>;

// ---- Function declarations -----------------------------------

Sums correlation_sum(const std::vector<BitPos> &input_diff, u64 samples, toy_util::Rng &rng);
double fwd_correlation(int stage, const u8 *fixed_key, u64 samples, toy_util::Rng &rng);

// ---- Main ----------------------------------------------------

int main(int argc, char **argv)
{
    const toy_util::Options options = toy_util::parse_options(argc, argv);
    for (int stage = 0; stage < STAGES; ++stage)
        toy_util::validate_positions(INPUT_DIFF_BITS[stage], OUTPUT_MASK_BITS[stage]);
    toy_util::Rng rng(options.seed);
    report_util::RunTimer timer;
    std::cout << "ToyChaCha distinguisher search\nStarted: " << timer.timestamp(timer.wall_start_) << '\n'
              << '\n' << report_util::section("Configuration") << '\n';
    report_util::ParamTable config(13);
    config.row("Cipher", "ToyChaCha (", KEY_SIZE_BITS, "-bit key, Dist round ", DIST_ROUND, ")");
    for (int stage = 0; stage < STAGES; ++stage)
        config.row(stage == 0 ? "Stage pairs" : "", stage + 1, ": ", string_util::join_bitpos(INPUT_DIFF_BITS[stage]),
                   " -> ", string_util::join_bitpos(OUTPUT_MASK_BITS[stage]));
    config.row("Samples/ID", report_util::fmt_log2(double(options.samples)))
        .row("Spread", report_util::fmt_log2(double(options.spread_keys)), " keys x ", report_util::fmt_log2(double(options.spread_ivs)), " IVs")
        .row("Seed", options.seed);
    std::cout << std::flush;

    // every single-bit ID against every single-bit OD
    std::vector<Sums> sums(ID_BITS);
    for (int id = 0; id < ID_BITS; ++id)
        sums[id] = correlation_sum({{u16(12 + id / 8), u16(id % 8)}}, options.samples, rng);

    // every stage's pair over random keys, and over random IVs of one key at a time
    std::vector<double> stage_eps;
    for (int stage = 0; stage < STAGES; ++stage)
        stage_eps.push_back(fwd_correlation(stage, nullptr, options.samples, rng));
    std::vector<std::vector<double>> per_key;
    for (u64 k = 0; k < options.spread_keys; ++k)
    {
        u8 key[8];
        toy_util::random_key(key, KEY_SIZE_BITS, rng);
        std::vector<double> eps;
        for (int stage = 0; stage < STAGES; ++stage) eps.push_back(fwd_correlation(stage, key, options.spread_ivs, rng));
        per_key.push_back(eps);
    }

    // the strongest pairs: TOP times, take the largest |eps_d| not taken yet
    std::cout << '\n' << report_util::section("Results") << '\n';
    report_util::ParamTable table(13);
    for (int stage = 0; stage < STAGES; ++stage)
        table.row(stage == 0 ? "Stage eps_d" : "", stage + 1, ": ", report_util::fmt_correlation(stage_eps[stage]));
    std::vector<std::pair<int, int>> strongest; // (id, od)
    std::vector<std::array<bool, OD_BITS>> taken(ID_BITS, std::array<bool, OD_BITS>{});
    for (int t = 0; t < TOP; ++t)
    {
        int best_id = -1, best_od = -1;
        for (int id = 0; id < ID_BITS; ++id)
            for (int od = 0; od < OD_BITS; ++od)
                if (!taken[id][od] && (best_id < 0 || std::llabs(sums[id][od]) > std::llabs(sums[best_id][best_od])))
                {
                    best_id = id;
                    best_od = od;
                }
        taken[best_id][best_od] = true;
        strongest.push_back({best_id, best_od});
        table.row(t == 0 ? "Strongest" : "", "{(", 12 + best_id / 8, ",", best_id % 8, ")} -> {(", best_od / 8, ",",
                  best_od % 8, ")}  ", report_util::fmt_correlation(double(sums[best_id][best_od]) / double(options.samples)));
    }

    std::ofstream out = toy_util::open_output(options);
    out << "{\n  \"key_size_bits\": " << KEY_SIZE_BITS << ",\n  \"dist_round\": " << DIST_ROUND
        << ",\n  \"samples\": " << options.samples << ",\n  \"seed\": " << options.seed
        << ",\n  \"fwd_eps\": " << toy_util::json_list(stage_eps) << ",\n  \"strongest\": [\n";
    for (std::size_t t = 0; t < strongest.size(); ++t)
    {
        const auto [id, od] = strongest[t];
        out << "    {\"id\": [" << 12 + id / 8 << ", " << id % 8 << "], \"od\": [" << od / 8 << ", " << od % 8
            << "], \"fwd_eps\": " << double(sums[id][od]) / double(options.samples) << "}"
            << (t + 1 < strongest.size() ? ",\n" : "\n");
    }
    out << "  ],\n  \"per_key_fwd_eps\": [";
    for (std::size_t k = 0; k < per_key.size(); ++k)
        out << toy_util::json_list(per_key[k]) << (k + 1 < per_key.size() ? ", " : "");
    out << "]\n}\n";

    std::cout << '\n' << report_util::section("Summary") << '\n';
    report_util::ParamTable(13).row("Elapsed", report_util::format_duration(timer.elapsed()));
    return 0;
}

// ---- Workers -------------------------------------------------

// Signed sums of every single OD bit for one input difference: +1 when Delta = 0, -1 otherwise.
Sums correlation_sum(const std::vector<BitPos> &input_diff, u64 samples, toy_util::Rng &rng)
{
    Sums sums{};
    for (u64 sample = 0; sample < samples; ++sample)
    {
        u8 key[8], iv[4], x0[16], dx0[16];
        toy_util::random_key(key, KEY_SIZE_BITS, rng);
        toy_util::random_iv(iv, rng);
        INIT_STATE(x0, key, iv);
        state_ops::copy_state(dx0, x0);
        for (const auto &[word, bit] : input_diff) dx0[word] ^= u8(1u << bit);

        for (int step = 0; step < DIST_STEP; ++step)
        {
            ROUND_STEP(x0, step);
            ROUND_STEP(dx0, step);
        }
        for (int od = 0; od < OD_BITS; ++od)
            sums[od] += ((x0[od / 8] ^ dx0[od / 8]) >> (od % 8) & 1) ? -1 : 1;
    }
    return sums;
}

// eps_d of one stage's pair; with a fixed key only the IVs vary.
double fwd_correlation(int stage, const u8 *fixed_key, u64 samples, toy_util::Rng &rng)
{
    std::int64_t sum = 0;
    for (u64 sample = 0; sample < samples; ++sample)
    {
        u8 key[8], iv[4], x0[16], dx0[16];
        if (fixed_key) state_ops::copy_state(key, fixed_key, 0, 8);
        else toy_util::random_key(key, KEY_SIZE_BITS, rng);
        toy_util::random_iv(iv, rng);
        INIT_STATE(x0, key, iv);
        state_ops::copy_state(dx0, x0);
        for (const auto &[word, bit] : INPUT_DIFF_BITS[stage]) dx0[word] ^= u8(1u << bit);

        for (int step = 0; step < DIST_STEP; ++step)
        {
            ROUND_STEP(x0, step);
            ROUND_STEP(dx0, step);
        }
        sum += attack_util::parity_sign(attack_util::masked_parity(x0, dx0, OUTPUT_MASK_BITS[stage]), 0);
    }
    return double(sum) / double(samples);
}
