/*
 * ToyChaCha backward correlation with suitable IVs ([Mai16] chosen-IV attack, offline)
 * Hiren | NTU Singapore
 * Created: 2022 | Updated: 2026-10-24
 *
 * The ID-column bits and the other significant bits stay correct, every PNB is random.
 * eps_a = Pr(Gamma = Delta) - Pr(Gamma != Delta); the attack sees eps = Pr(Gamma = 0) -
 * Pr(Gamma = 1), which the paper approximates by eps_a * eps_d. Both are measured.
 *
 * run.py builds and runs it:  ./bwd_corr --seed S --samples N --out bwd_corr.json
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
#include <cstdint>
#include <iostream>

// ---- Function declarations -----------------------------------

void random_weak_key(u8 *key, toy_util::Rng &rng);
std::array<std::int64_t, 2> correlation_sum(u64 samples, toy_util::Rng &rng);

// ---- Main ----------------------------------------------------

int main(int argc, char **argv)
{
    const toy_util::Options options = toy_util::parse_options(argc, argv);
    toy_util::validate_positions(INPUT_DIFF_BITS, OUTPUT_MASK_BITS, true);
    toy_util::validate_suitable_iv(SUITABLE_IV, KEY_SIZE_BITS);
    toy_util::Rng rng(options.seed);
    report_util::RunTimer timer;
    std::cout << "ToyChaCha backward correlation with suitable IVs\nStarted: " << timer.timestamp(timer.wall_start_)
              << '\n' << '\n' << report_util::section("Configuration") << '\n';
    report_util::ParamTable(13)
        .row("Cipher", "ToyChaCha (", KEY_SIZE_BITS, "-bit key, ", TOTAL_ROUNDS, " rounds, Dist round ", DIST_ROUND, ")")
        .row("PNBs", PNB_BITS.size(), " random, the other key bits correct")
        .row("Samples", report_util::fmt_log2(double(options.samples)), " weak keys")
        .row("Seed", options.seed);
    std::cout << std::flush;

    const auto [same, zero] = correlation_sum(options.samples, rng);
    const double bwd_eps = double(same) / double(options.samples);
    const double eps = double(zero) / double(options.samples);

    std::cout << '\n' << report_util::section("Results") << '\n';
    report_util::ParamTable(13)
        .row("eps_a", report_util::fmt_correlation(bwd_eps))
        .row("eps", report_util::fmt_correlation(eps), " (measured directly)");

    std::ofstream out = toy_util::open_output(options);
    out << "{\n  \"key_size_bits\": " << KEY_SIZE_BITS << ",\n  \"samples\": " << options.samples
        << ",\n  \"seed\": " << options.seed << ",\n  \"bwd_eps\": " << bwd_eps
        << ",\n  \"eps_measured\": " << eps << "\n}\n";

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

// Returns the signed sums of (Gamma = Delta) and of (Gamma = 0).
std::array<std::int64_t, 2> correlation_sum(u64 samples, toy_util::Rng &rng)
{
    const auto [id_word, id_bit] = INPUT_DIFF_BITS[0];
    std::array<std::int64_t, 2> sums{};
    for (u64 sample = 0; sample < samples; ++sample)
    {
        u8 key[8], iv[4], x0[16], dx0[16], initial[16], dinitial[16];
        random_weak_key(key, rng);
        toy_util::random_iv(iv, rng);
        INIT_STATE(x0, key, iv);
        x0[id_word] = u8(SUITABLE_IV[toy_util::column_key(key, id_word % 4, KEY_SIZE_BITS)]);
        state_ops::copy_state(dx0, x0);
        dx0[id_word] ^= u8(1u << id_bit);
        state_ops::copy_state(initial, x0);
        state_ops::copy_state(dinitial, dx0);

        for (int step = 0; step < DIST_STEP; ++step)
        {
            ROUND_STEP(x0, step);
            ROUND_STEP(dx0, step);
        }
        const u8 fwd_parity = attack_util::masked_parity(x0, dx0, OUTPUT_MASK_BITS);
        for (int step = DIST_STEP; step < TOTAL_STEP; ++step)
        {
            ROUND_STEP(x0, step);
            ROUND_STEP(dx0, step);
        }
        u8 z[16], dz[16];
        state_ops::add_state(x0, initial, z);
        state_ops::add_state(dx0, dinitial, dz);

        // the attacker's view: significant bits correct, PNBs random
        u8 guessed[8], guess[16], dguess[16];
        state_ops::copy_state(guessed, key, 0, 8);
        for (const u16 bit : PNB_BITS) toy_util::set_key_bit(guessed, bit, u8(rng() >> 63), KEY_SIZE_BITS);
        state_ops::copy_state(guess, initial);
        state_ops::copy_state(dguess, dinitial);
        INSERT_KEY(guess, guessed);
        INSERT_KEY(dguess, guessed);

        u8 minusstate[16], dminusstate[16];
        state_ops::subtract_state(z, guess, minusstate);
        state_ops::subtract_state(dz, dguess, dminusstate);
        for (int step = TOTAL_STEP - 1; step >= DIST_STEP; --step)
        {
            INV_ROUND_STEP(minusstate, step);
            INV_ROUND_STEP(dminusstate, step);
        }
        const u8 bwd_parity = attack_util::masked_parity(minusstate, dminusstate, OUTPUT_MASK_BITS);
        sums[0] += attack_util::parity_sign(fwd_parity, bwd_parity);
        sums[1] += attack_util::parity_sign(bwd_parity, 0);
    }
    return sums;
}
