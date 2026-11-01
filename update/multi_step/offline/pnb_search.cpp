/*
 * ToyChaCha significant bits of every stage (multiple (ID, OD) attack, offline; Section 3.2)
 * Hiren | NTU Singapore
 * Created: 2022 | Updated: 2026-10-24
 *
 * Stage i uses (ID_i, OD_i). For every key bit not already in S_1, ..., S_(i-1): complement
 * it in X and X', go back from Z - X to DIST_ROUND and compare the OD_i difference with the
 * forward one; neutrality = Pr(same) - Pr(different). Bits below SIG_THRESHOLD form S_i.
 * The bits left after the last stage (REST) are found by exhaustive search in the attack.
 *
 * run.py builds and runs it:  ./pnb_search --seed S --samples N --out pnb_search.json
 */
#include "../../toychacha.hpp"
#include "../../toy_util.hpp"
#include "../../common_utility/attack_util.hpp"
#include "../../common_utility/core_types.hpp"
#include "../../common_utility/report_util.hpp"
#include "../../common_utility/state_ops.hpp"
#include "../../common_utility/string_ops.hpp"
#include "control_panel.hpp" // written by run.py

#include <cstdint>
#include <iostream>
#include <vector>

using Sums = std::vector<std::int64_t>;

// ---- Function declarations -----------------------------------

Sums correlation_sum(int stage, const std::vector<int> &stage_of, u64 samples, toy_util::Rng &rng);

// ---- Main ----------------------------------------------------

int main(int argc, char **argv)
{
    const toy_util::Options options = toy_util::parse_options(argc, argv);
    for (int stage = 0; stage < STAGES; ++stage)
        toy_util::validate_positions(INPUT_DIFF_BITS[stage], OUTPUT_MASK_BITS[stage]);
    toy_util::Rng rng(options.seed);
    report_util::RunTimer timer;
    std::cout << "ToyChaCha significant bits of every stage\nStarted: " << timer.timestamp(timer.wall_start_) << '\n'
              << '\n' << report_util::section("Configuration") << '\n';
    report_util::ParamTable(13)
        .row("Cipher", "ToyChaCha (", KEY_SIZE_BITS, "-bit key, ", TOTAL_ROUNDS, " rounds, Dist round ", DIST_ROUND, ")")
        .row("Stages", STAGES)
        .row("Threshold", "neutrality < ", SIG_THRESHOLD, " puts a bit in S_i")
        .row("Samples/bit", report_util::fmt_log2(double(options.samples)), " per stage")
        .row("Seed", options.seed);
    std::cout << std::flush;

    // stage_of[bit]: the stage whose S_i holds the bit (1, 2, ...), 0 while no stage took it
    std::vector<int> stage_of(KEY_SIZE_BITS, 0);
    std::vector<std::vector<double>> neutrality(STAGES, std::vector<double>(KEY_SIZE_BITS, 0.0));
    std::vector<std::vector<int>> measured_in(STAGES); // the stage_of of every bit when the stage began
    std::cout << '\n' << report_util::section("Results") << '\n';
    for (int stage = 0; stage < STAGES; ++stage)
    {
        measured_in[stage] = stage_of;
        const Sums sums = correlation_sum(stage, stage_of, options.samples, rng);
        std::cout << "stage " << stage + 1 << " (-- = taken by an earlier stage):\n";
        for (int bit = 0; bit < KEY_SIZE_BITS; ++bit)
        {
            neutrality[stage][bit] = double(sums[bit]) / double(options.samples);
            if (stage_of[bit] != 0) std::printf("  %2d:    --  ", bit);
            else std::printf("  %2d: %+.4f", bit, neutrality[stage][bit]);
            if (bit % 8 == 7) std::printf("\n");
        }
        for (int bit = 0; bit < KEY_SIZE_BITS; ++bit)
            if (stage_of[bit] == 0 && neutrality[stage][bit] < SIG_THRESHOLD) stage_of[bit] = stage + 1;
    }

    // the sets, byte by byte with the high bit first (the paper's order)
    std::vector<std::vector<int>> sig_bits(STAGES);
    std::vector<int> rest_bits;
    for (int word = 0; word < KEY_SIZE_BITS / 8; ++word)
        for (int bit = 8 * word + 7; bit >= 8 * word; --bit)
        {
            if (stage_of[bit] == 0) rest_bits.push_back(bit);
            else sig_bits[stage_of[bit] - 1].push_back(bit);
        }
    report_util::ParamTable table(13);
    for (int stage = 0; stage < STAGES; ++stage)
        table.row(stage == 0 ? "S_i" : "", stage + 1, ": ", sig_bits[stage].size(), " ", string_util::join_indices(sig_bits[stage]));
    table.row("Rest", rest_bits.size(), " ", string_util::join_indices(rest_bits));

    std::ofstream out = toy_util::open_output(options);
    out << "{\n  \"key_size_bits\": " << KEY_SIZE_BITS << ",\n  \"samples\": " << options.samples
        << ",\n  \"seed\": " << options.seed << ",\n  \"threshold\": " << SIG_THRESHOLD << ",\n  \"stages\": [\n";
    for (int stage = 0; stage < STAGES; ++stage)
    {
        // a bit an earlier stage had already taken was not measured in this one: null
        out << "    {\"neutrality\": [";
        for (int bit = 0; bit < KEY_SIZE_BITS; ++bit)
        {
            if (measured_in[stage][bit] != 0) out << "null";
            else out << neutrality[stage][bit];
            out << (bit + 1 < KEY_SIZE_BITS ? ", " : "");
        }
        out << "], \"sig_bits\": " << toy_util::json_list(sig_bits[stage]) << "}" << (stage + 1 < STAGES ? ",\n" : "\n");
    }
    out << "  ],\n  \"rest_bits\": " << toy_util::json_list(rest_bits) << "\n}\n";

    std::cout << '\n' << report_util::section("Summary") << '\n';
    report_util::ParamTable(13).row("Elapsed", report_util::format_duration(timer.elapsed()));
    return 0;
}

// ---- Worker --------------------------------------------------
// One stage: the forward calculation is shared by all candidate key bits; bits taken by an
// earlier stage are skipped (their sums stay 0).

Sums correlation_sum(int stage, const std::vector<int> &stage_of, u64 samples, toy_util::Rng &rng)
{
    Sums sums(KEY_SIZE_BITS, 0);
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

        for (int bit = 0; bit < KEY_SIZE_BITS; ++bit)
        {
            if (stage_of[bit] != 0) continue;
            // the initial states with key bit `bit` complemented
            u8 changed[8], guess[16], dguess[16];
            state_ops::copy_state(changed, key, 0, 8);
            toy_util::flip_key_bit(changed, bit, KEY_SIZE_BITS);
            state_ops::copy_state(guess, initial);
            state_ops::copy_state(dguess, dinitial);
            INSERT_KEY(guess, changed);
            INSERT_KEY(dguess, changed);

            u8 minusstate[16], dminusstate[16];
            state_ops::subtract_state(z, guess, minusstate);
            state_ops::subtract_state(dz, dguess, dminusstate);
            for (int step = TOTAL_STEP - 1; step >= DIST_STEP; --step)
            {
                INV_ROUND_STEP(minusstate, step);
                INV_ROUND_STEP(dminusstate, step);
            }
            const u8 bwd_parity = attack_util::masked_parity(minusstate, dminusstate, OUTPUT_MASK_BITS[stage]);
            sums[bit] += attack_util::parity_sign(fwd_parity, bwd_parity);
        }
    }
    return sums;
}
