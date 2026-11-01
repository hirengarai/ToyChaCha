/*
 * ToyChaCha backward correlation of every stage (multiple (ID, OD) attack, offline)
 * Hiren | NTU Singapore
 * Created: 2022 | Updated: 2026-10-24
 *
 * In stage i the bits of S_1, ..., S_i stay correct (recovered earlier, or guessed now) and
 * every other key bit is random. eps_a = Pr(Gamma = Delta) - Pr(Gamma != Delta) at OD_i; the
 * attack sees eps = Pr(Gamma = 0) - Pr(Gamma = 1), approximated by eps_a * eps_d. Both measured.
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
#include <vector>

// ---- Function declarations -----------------------------------

std::array<std::int64_t, 2> correlation_sum(int stage, const std::vector<bool> &known, u64 samples, toy_util::Rng &rng);

// ---- Main ----------------------------------------------------

int main(int argc, char **argv)
{
    const toy_util::Options options = toy_util::parse_options(argc, argv);
    for (int stage = 0; stage < STAGES; ++stage)
        toy_util::validate_positions(INPUT_DIFF_BITS[stage], OUTPUT_MASK_BITS[stage]);
    toy_util::Rng rng(options.seed);
    report_util::RunTimer timer;
    std::cout << "ToyChaCha backward correlation of every stage\nStarted: " << timer.timestamp(timer.wall_start_) << '\n'
              << '\n' << report_util::section("Configuration") << '\n';
    report_util::ParamTable(13)
        .row("Cipher", "ToyChaCha (", KEY_SIZE_BITS, "-bit key, ", TOTAL_ROUNDS, " rounds, Dist round ", DIST_ROUND, ")")
        .row("Stages", STAGES)
        .row("Samples", report_util::fmt_log2(double(options.samples)), " per stage")
        .row("Seed", options.seed);
    std::cout << std::flush;

    std::vector<bool> known(KEY_SIZE_BITS, false); // the bits of S_1, ..., S_i
    std::vector<double> bwd_eps, eps;
    std::cout << '\n' << report_util::section("Results") << '\n';
    report_util::ParamTable table(13);
    for (int stage = 0; stage < STAGES; ++stage)
    {
        for (const u16 bit : SIG_BITS[stage]) known[bit] = true;
        const auto [same, zero] = correlation_sum(stage, known, options.samples, rng);
        bwd_eps.push_back(double(same) / double(options.samples));
        eps.push_back(double(zero) / double(options.samples));
        table.row(stage == 0 ? "eps_a, eps" : "", stage + 1, ": ", report_util::fmt_correlation(bwd_eps.back()), ", ",
                  report_util::fmt_correlation(eps.back()), " (measured directly)");
    }

    std::ofstream out = toy_util::open_output(options);
    out << "{\n  \"key_size_bits\": " << KEY_SIZE_BITS << ",\n  \"samples\": " << options.samples
        << ",\n  \"seed\": " << options.seed << ",\n  \"bwd_eps\": " << toy_util::json_list(bwd_eps)
        << ",\n  \"eps_measured\": " << toy_util::json_list(eps) << "\n}\n";

    std::cout << '\n' << report_util::section("Summary") << '\n';
    report_util::ParamTable(13).row("Elapsed", report_util::format_duration(timer.elapsed()));
    return 0;
}

// ---- Worker --------------------------------------------------
// Returns the signed sums of (Gamma = Delta) and of (Gamma = 0) for one stage.

std::array<std::int64_t, 2> correlation_sum(int stage, const std::vector<bool> &known, u64 samples, toy_util::Rng &rng)
{
    std::array<std::int64_t, 2> sums{};
    for (u64 sample = 0; sample < samples; ++sample)
    {
        u8 key[8], iv[4], x0[16], dx0[16], initial[16], dinitial[16];
        toy_util::random_key(key, KEY_SIZE_BITS, rng);
        toy_util::random_iv(iv, rng);
        INIT_STATE(x0, key, iv);
        state_ops::copy_state(dx0, x0);
        for (const auto &[word, bit] : INPUT_DIFF_BITS[stage]) dx0[word] ^= u8(1u << bit);
        state_ops::copy_state(initial, x0);
        state_ops::copy_state(dinitial, dx0);

        for (int step = 0; step < DIST_STEP; ++step)
        {
            ROUND_STEP(x0, step);
            ROUND_STEP(dx0, step);
        }
        const u8 fwd_parity = attack_util::masked_parity(x0, dx0, OUTPUT_MASK_BITS[stage]);
        for (int step = DIST_STEP; step < TOTAL_STEP; ++step)
        {
            ROUND_STEP(x0, step);
            ROUND_STEP(dx0, step);
        }
        u8 z[16], dz[16];
        state_ops::add_state(x0, initial, z);
        state_ops::add_state(dx0, dinitial, dz);

        // the attacker's view in this stage: S_1..S_i correct, every other bit random
        u8 guessed[8], guess[16], dguess[16];
        state_ops::copy_state(guessed, key, 0, 8);
        for (int bit = 0; bit < KEY_SIZE_BITS; ++bit)
            if (!known[bit]) toy_util::set_key_bit(guessed, bit, u8(rng() >> 63), KEY_SIZE_BITS);
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
        const u8 bwd_parity = attack_util::masked_parity(minusstate, dminusstate, OUTPUT_MASK_BITS[stage]);
        sums[0] += attack_util::parity_sign(fwd_parity, bwd_parity);
        sums[1] += attack_util::parity_sign(bwd_parity, 0);
    }
    return sums;
}
