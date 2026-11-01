/*
 * ToyChaCha key recovery (multiple (ID, OD) attack, online; Section 3.2)
 * Hiren | NTU Singapore
 * Created: 2022 | Updated: 2026-10-24
 *
 * For each random master key the attacker collects N_i keystream pairs for every stage, then
 * recovers S_1, S_2 and S_3 one stage after the other with that stage's threshold test, and
 * finally searches the remaining bits exhaustively. One loop per stage: written for 3 stages.
 * --keys 1 shows the recovered key.
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
#include <array>
#include <iostream>
#include <vector>

static_assert(STAGES == 3, "key_recovery.cpp has one loop per stage: it is written for 3 stages");

// ---- Settings ------------------------------------------------

const std::array<u64, STAGES> SIG_VALUES = {
    toy_util::search_values(SIG_BITS[0].size()), toy_util::search_values(SIG_BITS[1].size()),
    toy_util::search_values(SIG_BITS[2].size())};

const u64 REST_VALUES = toy_util::search_values(REST_BITS.size()); // every value of the bits left for the end

// The attacker's data for one key: N_i IVs of every stage with and without its input difference
struct Data
{
    u8 x[STAGES][N_MAX][16], dx[STAGES][N_MAX][16], z[STAGES][N_MAX][16], dz[STAGES][N_MAX][16];
};

// Totals over all attacked keys, written to --out for the report
struct Totals
{
    u64 keys = 0, successes = 0, rest_work = 0;
    std::array<u64, STAGES> guesses{}, stage_work{}, false_alarms{};
};

// ---- Function declarations -----------------------------------

void collect_keystream(const u8 *master_key, Data &data, toy_util::Rng &rng);
void set_guess(u8 *key, const std::array<u64, STAGES> &guess, int stages);
bool crosses_threshold(int stage, const std::array<u64, STAGES> &guess, const Data &data, toy_util::Rng &rng);
bool is_master_key(const u8 *key, const Data &data);
bool recover_key(const u8 *master_key, Data &data, Totals &totals, u8 *recovered, toy_util::Rng &rng);

// ---- Main ----------------------------------------------------

int main(int argc, char **argv)
{
    const toy_util::Options options = toy_util::parse_options(argc, argv);
    for (int stage = 0; stage < STAGES; ++stage)
        toy_util::validate_positions(INPUT_DIFF_BITS[stage], OUTPUT_MASK_BITS[stage]);
    toy_util::validate_partition(KEY_SIZE_BITS, {SIG_BITS[0], SIG_BITS[1], SIG_BITS[2], REST_BITS});
    for (int stage = 0; stage < STAGES; ++stage)
        if (N[stage] == 0 || N[stage] > N_MAX || T[stage] == 0 || T[stage] > N[stage] || COUNT_VALUE[stage] > 1)
            toy_util::fail("invalid stage sample count or threshold");
    toy_util::Rng rng(options.seed);
    report_util::RunTimer timer;
    std::cout << "ToyChaCha multiple (ID, OD) key recovery\nStarted: " << timer.timestamp(timer.wall_start_) << '\n'
              << '\n' << report_util::section("Configuration") << '\n';
    report_util::ParamTable config(13);
    config.row("Cipher", "ToyChaCha (", KEY_SIZE_BITS, "-bit key, ", TOTAL_ROUNDS, " rounds, Dist round ", DIST_ROUND, ")");
    for (int stage = 0; stage < STAGES; ++stage)
        config.row(stage == 0 ? "Stages" : "", stage + 1, ": ", string_util::join_bitpos(INPUT_DIFF_BITS[stage]), " -> ",
                   string_util::join_bitpos(OUTPUT_MASK_BITS[stage]), ", ", SIG_BITS[stage].size(), " bits, N = ",
                   N[stage], ", T = ", T[stage]);
    config.row("Rest", REST_BITS.size(), " bits, exhaustive")
        .row("Keys", options.keys)
        .row("Seed", options.seed);
    std::cout << std::flush;

    static Data data;
    Totals totals;
    for (u64 k = 0; k < options.keys; ++k)
    {
        u8 master_key[8], recovered[8]{};
        toy_util::random_key(master_key, KEY_SIZE_BITS, rng);
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
                std::cout << "❌ The master key was not recovered: a correct guess missed its threshold\n";
        }
        else if ((k + 1) % 1024 == 0)
            std::cout << "  " << k + 1 << " keys done, " << totals.successes << " recovered\n" << std::flush;
    }

    std::ofstream out = toy_util::open_output(options);
    out << "{\n  \"keys\": " << totals.keys << ",\n  \"successes\": " << totals.successes
        << ",\n  \"guesses\": " << toy_util::json_list(totals.guesses)
        << ",\n  \"stage_work\": " << toy_util::json_list(totals.stage_work)
        << ",\n  \"false_alarms\": " << toy_util::json_list(totals.false_alarms)
        << ",\n  \"rest_work\": " << totals.rest_work
        << ",\n  \"seconds\": " << double(timer.elapsed().count()) / 1000 << "\n}\n";

    std::cout << '\n' << report_util::section("Summary") << '\n';
    report_util::ParamTable(13)
        .row("Recovered", totals.successes, " of ", totals.keys, " keys")
        .row("Elapsed", report_util::format_duration(timer.elapsed()));
    return 0;
}

// ---- Workers -------------------------------------------------

// For every stage, N_i random IVs, the same IVs with that stage's input difference, and their keystreams
void collect_keystream(const u8 *master_key, Data &data, toy_util::Rng &rng)
{
    for (int stage = 0; stage < STAGES; ++stage)
        for (u64 i = 0; i < N[stage]; ++i)
        {
            u8 iv[4];
            toy_util::random_iv(iv, rng);
            INIT_STATE(data.x[stage][i], master_key, iv);
            state_ops::copy_state(data.dx[stage][i], data.x[stage][i]);
            for (const auto &[word, bit] : INPUT_DIFF_BITS[stage]) data.dx[stage][i][word] ^= u8(1u << bit);

            u8 x0[16], dx0[16];
            state_ops::copy_state(x0, data.x[stage][i]);
            state_ops::copy_state(dx0, data.dx[stage][i]);
            for (int step = 0; step < TOTAL_STEP; ++step)
            {
                ROUND_STEP(x0, step);
                ROUND_STEP(dx0, step);
            }
            state_ops::add_state(x0, data.x[stage][i], data.z[stage][i]);
            state_ops::add_state(dx0, data.dx[stage][i], data.dz[stage][i]);
        }
}

// The guessed (or already recovered) bits of S_1, ..., S_stages.
void set_guess(u8 *key, const std::array<u64, STAGES> &guess, int stages)
{
    for (int s = 0; s < stages; ++s) toy_util::set_key_bits(key, SIG_BITS[s], guess[s], KEY_SIZE_BITS);
}

// The threshold test of one stage: S_1..S_stage as guessed, every other key bit random in every sample.
bool crosses_threshold(int stage, const std::array<u64, STAGES> &guess, const Data &data, toy_util::Rng &rng)
{
    u64 count = 0;
    for (u64 i = 0; i < N[stage]; ++i)
    {
        u8 guessed[8], x[16], dx[16];
        toy_util::random_key(guessed, KEY_SIZE_BITS, rng);
        set_guess(guessed, guess, stage + 1);
        state_ops::copy_state(x, data.x[stage][i]);
        state_ops::copy_state(dx, data.dx[stage][i]);
        INSERT_KEY(x, guessed);
        INSERT_KEY(dx, guessed);

        u8 minusstate[16], dminusstate[16];
        state_ops::subtract_state(data.z[stage][i], x, minusstate);
        state_ops::subtract_state(data.dz[stage][i], dx, dminusstate);
        for (int step = TOTAL_STEP - 1; step >= DIST_STEP; --step)
        {
            INV_ROUND_STEP(minusstate, step);
            INV_ROUND_STEP(dminusstate, step);
        }
        if (attack_util::masked_parity(minusstate, dminusstate, OUTPUT_MASK_BITS[stage]) == COUNT_VALUE[stage])
            ++count;
    }
    return count >= T[stage];
}

// A candidate is the master key if it gives the first stored keystream block.
bool is_master_key(const u8 *key, const Data &data)
{
    u8 initial[16], x0[16], z[16];
    state_ops::copy_state(initial, data.x[0][0]);
    INSERT_KEY(initial, key);
    state_ops::copy_state(x0, initial);
    for (int step = 0; step < TOTAL_STEP; ++step) ROUND_STEP(x0, step);
    state_ops::add_state(x0, initial, z);
    return std::equal(z, z + 16, data.z[0][0]);
}

// Attack one master key; true if it was recovered. A crossing with a wrong guess is a false alarm.
bool recover_key(const u8 *master_key, Data &data, Totals &totals, u8 *recovered, toy_util::Rng &rng)
{
    collect_keystream(master_key, data, rng);
    std::array<u64, STAGES> truth{}, guess{};
    for (int stage = 0; stage < STAGES; ++stage) truth[stage] = toy_util::get_key_bits(master_key, SIG_BITS[stage]);
    bool found = false;

    // stage 1: guess S_1
    for (guess[0] = 0; guess[0] < SIG_VALUES[0] && !found; ++guess[0])
    {
        ++totals.guesses[0];
        totals.stage_work[0] += N[0];
        if (!crosses_threshold(0, guess, data, rng)) continue;
        if (guess[0] != truth[0]) ++totals.false_alarms[0];

        // stage 2: S_1 as found, guess S_2
        for (guess[1] = 0; guess[1] < SIG_VALUES[1] && !found; ++guess[1])
        {
            ++totals.guesses[1];
            totals.stage_work[1] += N[1];
            if (!crosses_threshold(1, guess, data, rng)) continue;
            if (guess[0] != truth[0] || guess[1] != truth[1]) ++totals.false_alarms[1];

            // stage 3: S_1 and S_2 as found, guess S_3
            for (guess[2] = 0; guess[2] < SIG_VALUES[2] && !found; ++guess[2])
            {
                ++totals.guesses[2];
                totals.stage_work[2] += N[2];
                if (!crosses_threshold(2, guess, data, rng)) continue;
                if (guess != truth) ++totals.false_alarms[2];

                // last stage: search all values of the remaining bits
                for (u64 rest = 0; rest < REST_VALUES && !found; ++rest)
                {
                    u8 candidate[8]{};
                    set_guess(candidate, guess, STAGES);
                    toy_util::set_key_bits(candidate, REST_BITS, rest, KEY_SIZE_BITS);
                    ++totals.rest_work;
                    if (is_master_key(candidate, data))
                    {
                        found = true;
                        state_ops::copy_state(recovered, candidate, 0, 8);
                    }
                }
            }
        }
    }
    ++totals.keys;
    if (found) ++totals.successes;
    return found;
}
