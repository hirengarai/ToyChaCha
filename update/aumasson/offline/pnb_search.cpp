/*
 * ToyChaCha PNB search ([AFK+08] attack, offline)
 * Hiren | NTU Singapore
 * Created: 2022 | Updated: 2026-10-24
 *
 * For every key bit: complement it in X and X', compute Z - X and Z' - X' with the changed
 * key, go back to DIST_ROUND and compare the OD difference with the forward one. The
 * neutrality of the bit is Pr(same) - Pr(different); above PNB_THRESHOLD it is a PNB.
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

Sums correlation_sum(u64 samples, toy_util::Rng &rng);

// ---- Main ----------------------------------------------------

int main(int argc, char **argv)
{
    const toy_util::Options options = toy_util::parse_options(argc, argv);
    toy_util::validate_positions(INPUT_DIFF_BITS, OUTPUT_MASK_BITS);
    toy_util::Rng rng(options.seed);
    report_util::RunTimer timer;
    std::cout << "ToyChaCha PNB search\nStarted: " << timer.timestamp(timer.wall_start_) << '\n'
              << '\n' << report_util::section("Configuration") << '\n';
    report_util::ParamTable(13)
        .row("Cipher", "ToyChaCha (", KEY_SIZE_BITS, "-bit key, ", TOTAL_ROUNDS, " rounds, Dist round ", DIST_ROUND, ")")
        .row("Input Diff", string_util::join_bitpos(INPUT_DIFF_BITS))
        .row("Mask Bits", string_util::join_bitpos(OUTPUT_MASK_BITS))
        .row("Threshold", "neutrality > ", PNB_THRESHOLD)
        .row("Samples/bit", report_util::fmt_log2(double(options.samples)))
        .row("Seed", options.seed);
    std::cout << std::flush;

    const Sums sums = correlation_sum(options.samples, rng);

    // PNBs and significant bits, byte by byte with the high bit first (the paper's order)
    std::vector<double> neutrality(KEY_SIZE_BITS);
    std::vector<int> pnb_bits, sig_bits;
    for (int bit = 0; bit < KEY_SIZE_BITS; ++bit) neutrality[bit] = double(sums[bit]) / double(options.samples);
    for (int word = 0; word < KEY_SIZE_BITS / 8; ++word)
        for (int bit = 8 * word + 7; bit >= 8 * word; --bit)
        {
            if (neutrality[bit] > PNB_THRESHOLD) pnb_bits.push_back(bit);
            else sig_bits.push_back(bit);
        }

    std::cout << '\n' << report_util::section("Results") << '\n';
    for (int bit = 0; bit < KEY_SIZE_BITS; ++bit)
        std::printf("  %2d: %+.4f%s", bit, neutrality[bit], bit % 8 == 7 ? "\n" : "");
    report_util::ParamTable(13)
        .row("PNBs", pnb_bits.size(), " ", string_util::join_indices(pnb_bits))
        .row("Significant", sig_bits.size(), " ", string_util::join_indices(sig_bits));

    std::ofstream out = toy_util::open_output(options);
    out << "{\n  \"key_size_bits\": " << KEY_SIZE_BITS << ",\n  \"samples\": " << options.samples
        << ",\n  \"seed\": " << options.seed << ",\n  \"threshold\": " << PNB_THRESHOLD
        << ",\n  \"neutrality\": " << toy_util::json_list(neutrality)
        << ",\n  \"pnb_bits\": " << toy_util::json_list(pnb_bits)
        << ",\n  \"sig_bits\": " << toy_util::json_list(sig_bits) << "\n}\n";

    std::cout << '\n' << report_util::section("Summary") << '\n';
    report_util::ParamTable(13).row("Elapsed", report_util::format_duration(timer.elapsed()));
    return 0;
}

// ---- Worker --------------------------------------------------
// The forward calculation is shared by all candidate key bits.

Sums correlation_sum(u64 samples, toy_util::Rng &rng)
{
    Sums sums(KEY_SIZE_BITS, 0);
    for (u64 sample = 0; sample < samples; ++sample)
    {
        u8 key[8], iv[4], x0[16], dx0[16], initial[16], dinitial[16];
        toy_util::random_key(key, KEY_SIZE_BITS, rng);
        toy_util::random_iv(iv, rng);
        INIT_STATE(x0, key, iv);
        state_ops::copy_state(dx0, x0);
        for (const auto &[word, bit] : INPUT_DIFF_BITS) dx0[word] ^= u8(1u << bit);
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

        // the keystream blocks Z = X^R + X
        u8 z[16], dz[16];
        state_ops::add_state(x0, initial, z);
        state_ops::add_state(dx0, dinitial, dz);

        for (int bit = 0; bit < KEY_SIZE_BITS; ++bit)
        {
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
            const u8 bwd_parity = attack_util::masked_parity(minusstate, dminusstate, OUTPUT_MASK_BITS);
            sums[bit] += attack_util::parity_sign(fwd_parity, bwd_parity);
        }
    }
    return sums;
}
