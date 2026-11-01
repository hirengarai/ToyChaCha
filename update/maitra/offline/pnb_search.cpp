/*
 * ToyChaCha PNB search with suitable IVs ([Mai16] chosen-IV attack, offline)
 * Hiren | NTU Singapore
 * Created: 2022 | Updated: 2026-10-24
 *
 * As in [AFK+08]: complement one key bit in X and X', go back from Z - X to DIST_ROUND and
 * compare the OD difference with the forward one; neutrality = Pr(same) - Pr(different).
 * The key words of the ID column decide the IV, so their bits are never PNBs [Mai16]:
 * they are the ID_SIG bits. Of the other bits, neutrality above PNB_THRESHOLD makes a PNB.
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

#include <algorithm>
#include <cstdint>
#include <iostream>
#include <vector>

using Sums = std::vector<std::int64_t>;

// ---- Function declarations -----------------------------------

void random_weak_key(u8 *key, toy_util::Rng &rng);
Sums correlation_sum(u64 samples, toy_util::Rng &rng);

// ---- Main ----------------------------------------------------

int main(int argc, char **argv)
{
    const toy_util::Options options = toy_util::parse_options(argc, argv);
    toy_util::validate_positions(INPUT_DIFF_BITS, OUTPUT_MASK_BITS, true);
    toy_util::validate_suitable_iv(SUITABLE_IV, KEY_SIZE_BITS);
    toy_util::Rng rng(options.seed);
    report_util::RunTimer timer;
    std::cout << "ToyChaCha PNB search with suitable IVs\nStarted: " << timer.timestamp(timer.wall_start_) << '\n'
              << '\n' << report_util::section("Configuration") << '\n';
    report_util::ParamTable(13)
        .row("Cipher", "ToyChaCha (", KEY_SIZE_BITS, "-bit key, ", TOTAL_ROUNDS, " rounds, Dist round ", DIST_ROUND, ")")
        .row("Input Diff", string_util::join_bitpos(INPUT_DIFF_BITS))
        .row("Mask Bits", string_util::join_bitpos(OUTPUT_MASK_BITS))
        .row("Threshold", "neutrality > ", PNB_THRESHOLD)
        .row("Samples/bit", report_util::fmt_log2(double(options.samples)), " weak keys")
        .row("Seed", options.seed);
    std::cout << std::flush;

    const Sums sums = correlation_sum(options.samples, rng);

    // ID_SIG, PNBs and the other significant bits, byte by byte with the high bit first
    const std::vector<u16> id_sig_bits = toy_util::column_key_bits(INPUT_DIFF_BITS[0].first % 4, KEY_SIZE_BITS);
    std::vector<double> neutrality(KEY_SIZE_BITS);
    std::vector<int> pnb_bits, sig_bits;
    for (int bit = 0; bit < KEY_SIZE_BITS; ++bit) neutrality[bit] = double(sums[bit]) / double(options.samples);
    for (int word = 0; word < KEY_SIZE_BITS / 8; ++word)
        for (int bit = 8 * word + 7; bit >= 8 * word; --bit)
        {
            if (std::find(id_sig_bits.begin(), id_sig_bits.end(), bit) != id_sig_bits.end()) continue;
            if (neutrality[bit] > PNB_THRESHOLD) pnb_bits.push_back(bit);
            else sig_bits.push_back(bit);
        }

    std::cout << '\n' << report_util::section("Results") << '\n';
    for (int bit = 0; bit < KEY_SIZE_BITS; ++bit)
        std::printf("  %2d: %+.4f%s", bit, neutrality[bit], bit % 8 == 7 ? "\n" : "");
    report_util::ParamTable(13)
        .row("ID column", id_sig_bits.size(), " ", string_util::join_indices(id_sig_bits))
        .row("PNBs", pnb_bits.size(), " ", string_util::join_indices(pnb_bits))
        .row("Significant", sig_bits.size(), " ", string_util::join_indices(sig_bits));

    std::ofstream out = toy_util::open_output(options);
    out << "{\n  \"key_size_bits\": " << KEY_SIZE_BITS << ",\n  \"samples\": " << options.samples
        << ",\n  \"seed\": " << options.seed << ",\n  \"threshold\": " << PNB_THRESHOLD
        << ",\n  \"neutrality\": " << toy_util::json_list(neutrality)
        << ",\n  \"id_sig_bits\": " << toy_util::json_list(id_sig_bits)
        << ",\n  \"pnb_bits\": " << toy_util::json_list(pnb_bits)
        << ",\n  \"sig_bits\": " << toy_util::json_list(sig_bits) << "\n}\n";

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

// The forward calculation is shared by all candidate key bits; the IV stays the real key's.
Sums correlation_sum(u64 samples, toy_util::Rng &rng)
{
    const auto [id_word, id_bit] = INPUT_DIFF_BITS[0];
    Sums sums(KEY_SIZE_BITS, 0);
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
