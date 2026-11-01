/*
 * ToyChaCha distinguisher search with suitable IVs ([Mai16] chosen-IV attack, offline)
 * Hiren | NTU Singapore
 * Created: 2026 | Updated: 2026-10-24
 *
 * The ID is fixed by the suitable-IV table, so the search runs over every output bit after
 * DIST_ROUND rounds: eps_d = Pr(Delta = 0) - Pr(Delta = 1) with the suitable IV of the key,
 * and with a random IV for comparison. Strong keys are skipped: the attack does not apply
 * to them. Also reports how eps_d of the chosen pair spreads over keys (Section 5).
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

constexpr int OD_BITS = 128; // every bit of the state
constexpr int TOP = 10;      // strongest output bits to report

using Sums = std::array<std::int64_t, OD_BITS>;

// ---- Function declarations -----------------------------------

void random_weak_key(u8 *key, toy_util::Rng &rng);
void add_signs(const u8 *initial, Sums &sums);
void correlation_sum(u64 samples, Sums &suitable, Sums &random, toy_util::Rng &rng);
double fwd_correlation(const u8 *fixed_key, u64 samples, toy_util::Rng &rng);

// ---- Main ----------------------------------------------------

int main(int argc, char **argv)
{
    const toy_util::Options options = toy_util::parse_options(argc, argv);
    toy_util::validate_positions(INPUT_DIFF_BITS, OUTPUT_MASK_BITS, true);
    toy_util::validate_suitable_iv(SUITABLE_IV, KEY_SIZE_BITS);
    toy_util::Rng rng(options.seed);
    report_util::RunTimer timer;
    std::cout << "ToyChaCha distinguisher search with suitable IVs\nStarted: " << timer.timestamp(timer.wall_start_)
              << '\n' << '\n' << report_util::section("Configuration") << '\n';
    report_util::ParamTable(13)
        .row("Cipher", "ToyChaCha (", KEY_SIZE_BITS, "-bit key, Dist round ", DIST_ROUND, ")")
        .row("Chosen pair", string_util::join_bitpos(INPUT_DIFF_BITS), " -> ", string_util::join_bitpos(OUTPUT_MASK_BITS))
        .row("Samples", report_util::fmt_log2(double(options.samples)), " weak keys")
        .row("Spread", report_util::fmt_log2(double(options.spread_keys)), " keys x ", report_util::fmt_log2(double(options.spread_ivs)), " IVs")
        .row("Seed", options.seed);
    std::cout << std::flush;

    Sums suitable{}, random{};
    correlation_sum(options.samples, suitable, random, rng);
    const auto [od_word, od_bit] = OUTPUT_MASK_BITS[0];
    const int chosen = 8 * od_word + od_bit;
    const double fwd_eps = double(suitable[chosen]) / double(options.samples);
    const double fwd_eps_random = double(random[chosen]) / double(options.samples);

    std::vector<double> per_key;
    for (u64 k = 0; k < options.spread_keys; ++k)
    {
        u8 key[8];
        random_weak_key(key, rng);
        per_key.push_back(fwd_correlation(key, options.spread_ivs, rng));
    }

    // the strongest output bits with suitable IVs: TOP times, take the largest |eps_d| not taken yet
    std::cout << '\n' << report_util::section("Results") << '\n';
    report_util::ParamTable table(13);
    table.row("Chosen eps_d", report_util::fmt_correlation(fwd_eps), " (random IVs: ", fwd_eps_random, ")");
    std::vector<int> strongest;
    std::array<bool, OD_BITS> taken{};
    for (int t = 0; t < TOP; ++t)
    {
        int best = -1;
        for (int od = 0; od < OD_BITS; ++od)
            if (!taken[od] && (best < 0 || std::llabs(suitable[od]) > std::llabs(suitable[best]))) best = od;
        taken[best] = true;
        strongest.push_back(best);
        table.row(t == 0 ? "Strongest" : "", "{(", best / 8, ",", best % 8, ")}  ",
                  report_util::fmt_correlation(double(suitable[best]) / double(options.samples)));
    }

    std::ofstream out = toy_util::open_output(options);
    out << "{\n  \"key_size_bits\": " << KEY_SIZE_BITS << ",\n  \"dist_round\": " << DIST_ROUND
        << ",\n  \"samples\": " << options.samples << ",\n  \"seed\": " << options.seed
        << ",\n  \"fwd_eps\": " << fwd_eps << ",\n  \"fwd_eps_random_iv\": " << fwd_eps_random
        << ",\n  \"strongest\": [\n";
    for (std::size_t t = 0; t < strongest.size(); ++t)
        out << "    {\"od\": [" << strongest[t] / 8 << ", " << strongest[t] % 8 << "], \"fwd_eps\": "
            << double(suitable[strongest[t]]) / double(options.samples) << ", \"fwd_eps_random_iv\": "
            << double(random[strongest[t]]) / double(options.samples) << "}" << (t + 1 < strongest.size() ? ",\n" : "\n");
    out << "  ],\n  \"per_key_fwd_eps\": " << toy_util::json_list(per_key) << "\n}\n";

    std::cout << '\n' << report_util::section("Summary") << '\n';
    report_util::ParamTable(13).row("Elapsed", report_util::format_duration(timer.elapsed()));
    return 0;
}

// ---- Workers -------------------------------------------------

// A random key whose ID column has a suitable IV.
void random_weak_key(u8 *key, toy_util::Rng &rng)
{
    const int column = INPUT_DIFF_BITS[0].first % 4;
    do toy_util::random_key(key, KEY_SIZE_BITS, rng);
    while (SUITABLE_IV[toy_util::column_key(key, column, KEY_SIZE_BITS)] < 0);
}

// Adds the signs of every single output bit of one initial state: +1 when Delta = 0, -1 otherwise.
void add_signs(const u8 *initial, Sums &sums)
{
    const auto [id_word, id_bit] = INPUT_DIFF_BITS[0];
    u8 x0[16], dx0[16];
    state_ops::copy_state(x0, initial);
    state_ops::copy_state(dx0, initial);
    dx0[id_word] ^= u8(1u << id_bit);
    for (int step = 0; step < DIST_STEP; ++step)
    {
        ROUND_STEP(x0, step);
        ROUND_STEP(dx0, step);
    }
    for (int od = 0; od < OD_BITS; ++od)
        sums[od] += ((x0[od / 8] ^ dx0[od / 8]) >> (od % 8) & 1) ? -1 : 1;
}

// Every sample is used twice: with the IV as drawn, then with the key's suitable IV byte at the ID.
void correlation_sum(u64 samples, Sums &suitable, Sums &random, toy_util::Rng &rng)
{
    const int id_word = INPUT_DIFF_BITS[0].first;
    for (u64 sample = 0; sample < samples; ++sample)
    {
        u8 key[8], iv[4], x0[16];
        random_weak_key(key, rng);
        toy_util::random_iv(iv, rng);
        INIT_STATE(x0, key, iv);
        add_signs(x0, random);
        x0[id_word] = u8(SUITABLE_IV[toy_util::column_key(key, id_word % 4, KEY_SIZE_BITS)]);
        add_signs(x0, suitable);
    }
}

// eps_d of the chosen pair with suitable IVs, for one fixed key: only the other IV words vary.
double fwd_correlation(const u8 *fixed_key, u64 samples, toy_util::Rng &rng)
{
    const auto [id_word, id_bit] = INPUT_DIFF_BITS[0];
    const u8 suitable = u8(SUITABLE_IV[toy_util::column_key(fixed_key, id_word % 4, KEY_SIZE_BITS)]);
    std::int64_t sum = 0;
    for (u64 sample = 0; sample < samples; ++sample)
    {
        u8 iv[4], x0[16], dx0[16];
        toy_util::random_iv(iv, rng);
        INIT_STATE(x0, fixed_key, iv);
        x0[id_word] = suitable;
        state_ops::copy_state(dx0, x0);
        dx0[id_word] ^= u8(1u << id_bit);
        for (int step = 0; step < DIST_STEP; ++step)
        {
            ROUND_STEP(x0, step);
            ROUND_STEP(dx0, step);
        }
        sum += attack_util::parity_sign(attack_util::masked_parity(x0, dx0, OUTPUT_MASK_BITS), 0);
    }
    return double(sum) / double(samples);
}
