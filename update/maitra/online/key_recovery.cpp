/*
 * ToyChaCha key recovery ([Mai16] chosen-IV attack, online)
 * Hiren | NTU Singapore
 * Created: 2022 | Updated: 2026-10-24
 *
 * For each random weak master key, guess the key words of the ID column first. For each
 * guess the attacker asks for N keystream pairs with that guess's suitable IV, then guesses
 * the other significant bits with the threshold test (PNBs random) and searches all PNB
 * values for every guess that passes. --keys 1 shows the recovered key.
 *
 * run.py builds and runs it:  ./key_recovery --seed S --keys K --out jobs/key_recovery_0.json
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
#include <iostream>

static_assert(N > 0 && T > 0 && T <= N, "N and T must be positive, with T <= N");
static_assert(COUNT_VALUE <= 1, "COUNT_VALUE must be 0 or 1");

// ---- Settings ------------------------------------------------

const int COLUMN = INPUT_DIFF_BITS[0].first % 4;                         // the column of the ID
const int COLUMN_KEYS = toy_util::column_key_values(KEY_SIZE_BITS);       // every guess of its key words
const u64 SIG_VALUES = toy_util::search_values(SIG_BITS.size());                         // every guess of the other significant bits
const u64 PNB_VALUES = toy_util::search_values(PNB_BITS.size());                         // every value of the PNBs

// The attacker's data for one guess of the column key: N IVs with and without the input difference
struct Data
{
    u8 x[N][16], dx[N][16], z[N][16], dz[N][16];
};

// Totals over all attacked keys, written to --out for the report
struct Totals
{
    u64 keys = 0, successes = 0, guesses = 0, wrong_guesses = 0, false_alarms = 0;
    u64 sig_work = 0, pnb_work = 0, false_work = 0, pfa_keys = 0;
    double pfa_sum = 0.0; // sum over keys of (false alarms / wrong guesses): the paper's average Pr_fa
};

// ---- Function declarations -----------------------------------

void collect_keystream(const u8 *master_key, int column_key, Data &data, toy_util::Rng &rng);
void set_guess(u8 *key, int column_key, u64 sig);
bool crosses_threshold(int column_key, u64 sig, const Data &data, toy_util::Rng &rng);
bool is_master_key(const u8 *key, const Data &data);
bool recover_key(const u8 *master_key, Data &data, Totals &totals, u8 *recovered, toy_util::Rng &rng);

// ---- Main ----------------------------------------------------

int main(int argc, char **argv)
{
    const toy_util::Options options = toy_util::parse_options(argc, argv);
    toy_util::validate_positions(INPUT_DIFF_BITS, OUTPUT_MASK_BITS, true);
    toy_util::validate_suitable_iv(SUITABLE_IV, KEY_SIZE_BITS);
    toy_util::validate_partition(KEY_SIZE_BITS, {ID_SIG_BITS, SIG_BITS, PNB_BITS});
    toy_util::Rng rng(options.seed);
    report_util::RunTimer timer;
    std::cout << "ToyChaCha chosen-IV key recovery\nStarted: " << timer.timestamp(timer.wall_start_) << '\n'
              << '\n' << report_util::section("Configuration") << '\n';
    report_util::ParamTable(13)
        .row("Cipher", "ToyChaCha (", KEY_SIZE_BITS, "-bit key, ", TOTAL_ROUNDS, " rounds, Dist round ", DIST_ROUND, ")")
        .row("Input Diff", string_util::join_bitpos(INPUT_DIFF_BITS), " in column ", COLUMN)
        .row("Mask Bits", string_util::join_bitpos(OUTPUT_MASK_BITS))
        .row("Key bits", "column key + ", SIG_BITS.size(), " significant, ", PNB_BITS.size(), " PNBs")
        .row("N, T", N, ", ", T)
        .row("Keys", options.keys, " weak")
        .row("Seed", options.seed);
    std::cout << std::flush;

    static Data data; // about 12 KB: kept off the stack
    Totals totals;
    for (u64 k = 0; k < options.keys; ++k)
    {
        // a weak key: the attack applies only to keys whose ID column has a suitable IV
        u8 master_key[8], recovered[8]{};
        do toy_util::random_key(master_key, KEY_SIZE_BITS, rng);
        while (SUITABLE_IV[toy_util::column_key(master_key, COLUMN, KEY_SIZE_BITS)] < 0);

        const bool found = recover_key(master_key, data, totals, recovered, rng);
        if (options.keys == 1)
        {
            std::cout << '\n';
            report_util::print_state_hex(master_key, 8, 4, "The OG master key is");
            if (found)
            {
                std::cout << "✅ Hurray !!! The master key recovery is successful and the master key is\n";
                report_util::print_state_hex(recovered, 8, 4);
            }
            else
                std::cout << "❌ The master key was not recovered: the correct guess missed the threshold\n";
        }
        else if ((k + 1) % 64 == 0)
            std::cout << "  " << k + 1 << " keys done, " << totals.successes << " recovered\n" << std::flush;
    }

    std::ofstream out = toy_util::open_output(options);
    out << "{\n  \"keys\": " << totals.keys << ",\n  \"successes\": " << totals.successes
        << ",\n  \"guesses\": " << totals.guesses << ",\n  \"wrong_guesses\": " << totals.wrong_guesses
        << ",\n  \"false_alarms\": " << totals.false_alarms << ",\n  \"sig_work\": " << totals.sig_work
        << ",\n  \"pnb_work\": " << totals.pnb_work << ",\n  \"false_work\": " << totals.false_work
        << ",\n  \"pfa_sum\": " << totals.pfa_sum << ",\n  \"pfa_keys\": " << totals.pfa_keys
        << ",\n  \"seconds\": " << double(timer.elapsed().count()) / 1000 << "\n}\n";

    std::cout << '\n' << report_util::section("Summary") << '\n';
    report_util::ParamTable(13)
        .row("Recovered", totals.successes, " of ", totals.keys, " keys")
        .row("Elapsed", report_util::format_duration(timer.elapsed()));
    return 0;
}

// ---- Workers -------------------------------------------------

// N IVs carrying the suitable IV byte of one column-key guess (the other IV words random),
// the same IVs with the input difference, and their keystreams Z = X^R + X
void collect_keystream(const u8 *master_key, int column_key, Data &data, toy_util::Rng &rng)
{
    const auto [id_word, id_bit] = INPUT_DIFF_BITS[0];
    for (u64 i = 0; i < N; ++i)
    {
        u8 iv[4];
        toy_util::random_iv(iv, rng);
        INIT_STATE(data.x[i], master_key, iv);
        data.x[i][id_word] = u8(SUITABLE_IV[column_key]);
        state_ops::copy_state(data.dx[i], data.x[i]);
        data.dx[i][id_word] ^= u8(1u << id_bit);

        u8 x0[16], dx0[16];
        state_ops::copy_state(x0, data.x[i]);
        state_ops::copy_state(dx0, data.dx[i]);
        for (int step = 0; step < TOTAL_STEP; ++step)
        {
            ROUND_STEP(x0, step);
            ROUND_STEP(dx0, step);
        }
        state_ops::add_state(x0, data.x[i], data.z[i]);
        state_ops::add_state(dx0, data.dx[i], data.dz[i]);
    }
}

// The guessed key words of the column, and the guessed other significant bits.
void set_guess(u8 *key, int column_key, u64 sig)
{
    toy_util::set_column_key(key, COLUMN, column_key, KEY_SIZE_BITS);
    toy_util::set_key_bits(key, SIG_BITS, sig, KEY_SIZE_BITS);
}

// The threshold test of one guess; every PNB is random in every sample.
bool crosses_threshold(int column_key, u64 sig, const Data &data, toy_util::Rng &rng)
{
    u64 count = 0;
    for (u64 i = 0; i < N; ++i)
    {
        u8 guessed[8], guess[16], dguess[16];
        toy_util::random_key(guessed, KEY_SIZE_BITS, rng);
        set_guess(guessed, column_key, sig);
        state_ops::copy_state(guess, data.x[i]);
        state_ops::copy_state(dguess, data.dx[i]);
        INSERT_KEY(guess, guessed);
        INSERT_KEY(dguess, guessed);

        u8 minusstate[16], dminusstate[16];
        state_ops::subtract_state(data.z[i], guess, minusstate);
        state_ops::subtract_state(data.dz[i], dguess, dminusstate);
        for (int step = TOTAL_STEP - 1; step >= DIST_STEP; --step)
        {
            INV_ROUND_STEP(minusstate, step);
            INV_ROUND_STEP(dminusstate, step);
        }
        if (attack_util::masked_parity(minusstate, dminusstate, OUTPUT_MASK_BITS) == COUNT_VALUE)
            ++count;
    }
    return count >= T;
}

// A candidate is the master key if it gives the first stored keystream block.
bool is_master_key(const u8 *key, const Data &data)
{
    u8 initial[16], x0[16], z[16];
    state_ops::copy_state(initial, data.x[0]);
    INSERT_KEY(initial, key);
    state_ops::copy_state(x0, initial);
    for (int step = 0; step < TOTAL_STEP; ++step) ROUND_STEP(x0, step);
    state_ops::add_state(x0, initial, z);
    return std::equal(z, z + 16, data.z[0]);
}

// Attack one master key; true if it was recovered.
bool recover_key(const u8 *master_key, Data &data, Totals &totals, u8 *recovered, toy_util::Rng &rng)
{
    u64 tried = 0, alarms = 0;
    bool found = false;
    bool tried_correct = false;
    const u64 correct_sig = toy_util::get_key_bits(master_key, SIG_BITS);
    const int correct_column = toy_util::column_key(master_key, COLUMN, KEY_SIZE_BITS);

    for (int column_key = 0; column_key < COLUMN_KEYS && !found; ++column_key)
    {
        if (SUITABLE_IV[column_key] < 0) continue; // a strong column key has no suitable IV: never guessed

        collect_keystream(master_key, column_key, data, rng);
        for (u64 sig = 0; sig < SIG_VALUES && !found; ++sig)
        {
            ++tried;
            tried_correct |= column_key == correct_column && sig == correct_sig;
            if (!crosses_threshold(column_key, sig, data, rng)) continue;

            // the guess passed the test: search all values of the PNBs
            u64 searched = 0;
            for (u64 pnb = 0; pnb < PNB_VALUES && !found; ++pnb)
            {
                u8 candidate[8]{};
                set_guess(candidate, column_key, sig);
                toy_util::set_key_bits(candidate, PNB_BITS, pnb, KEY_SIZE_BITS);
                ++searched;
                if (is_master_key(candidate, data))
                {
                    found = true;
                    state_ops::copy_state(recovered, candidate, 0, 8);
                }
            }
            if (found) totals.pnb_work += searched;
            else
            {
                ++alarms; // a wrong guess passed the test: a false alarm
                totals.false_work += searched;
            }
        }
    }

    const u64 wrong = tried - (tried_correct ? 1 : 0);
    ++totals.keys;
    totals.guesses += tried;
    totals.wrong_guesses += wrong;
    totals.false_alarms += alarms;
    totals.sig_work += tried * N;
    if (wrong > 0)
    {
        totals.pfa_sum += double(alarms) / double(wrong);
        ++totals.pfa_keys;
    }
    if (found) ++totals.successes;
    return found;
}
