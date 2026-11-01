/*
 * ToyChaCha weak-key search ([Mai16] chosen-IV attack, offline)
 * Hiren | NTU Singapore
 * Created: 2022 | Updated: 2026-10-24
 *
 * The ID sits in IV word w, in column c = w % 4. After one round that column depends only
 * on its key words (c and c + 4) and on the IV byte at w. For every column key and every
 * IV byte, the Hamming weight of the difference after one round; the smallest weight over
 * everything makes an IV suitable. A column key with a suitable IV is weak, else strong.
 *
 * run.py builds and runs it:  ./weak_key_search --out weak_key_search.json
 */
#include "../../toychacha.hpp"
#include "../../toy_util.hpp"
#include "../../common_utility/attack_util.hpp"
#include "../../common_utility/core_types.hpp"
#include "../../common_utility/report_util.hpp"
#include "../../common_utility/state_ops.hpp"
#include "../../common_utility/string_ops.hpp"
#include "control_panel.hpp" // written by run.py

#include <bit>
#include <iostream>
#include <vector>

// ---- Main ----------------------------------------------------

int main(int argc, char **argv)
{
    const toy_util::Options options = toy_util::parse_options(argc, argv);
    toy_util::validate_positions(INPUT_DIFF_BITS, OUTPUT_MASK_BITS, true);
    toy_util::Rng rng(options.seed);
    const auto [id_word, id_bit] = INPUT_DIFF_BITS[0];
    const int column = id_word % 4;
    const int column_keys = toy_util::column_key_values(KEY_SIZE_BITS);
    report_util::RunTimer timer;
    std::cout << "ToyChaCha weak-key search\nStarted: " << timer.timestamp(timer.wall_start_) << '\n'
              << '\n' << report_util::section("Configuration") << '\n';
    report_util::ParamTable(13)
        .row("Cipher", "ToyChaCha (", KEY_SIZE_BITS, "-bit key), one round")
        .row("Input Diff", string_util::join_bitpos(INPUT_DIFF_BITS), " in column ", column)
        .row("Column keys", column_keys, " values x 256 IV bytes");
    std::cout << std::flush;

    // weight[k][v]: the Hamming weight of the difference after one round
    std::vector<std::vector<int>> weight(column_keys, std::vector<int>(256));
    int fewest = 128;
    for (int k = 0; k < column_keys; ++k)
        for (int v = 0; v < 256; ++v)
        {
            // the other key and IV words are random: they do not reach this column in one round
            u8 key[8], iv[4], x0[16], dx0[16];
            toy_util::random_key(key, KEY_SIZE_BITS, rng);
            toy_util::set_column_key(key, column, k, KEY_SIZE_BITS);
            toy_util::random_iv(iv, rng);
            INIT_STATE(x0, key, iv);
            x0[id_word] = u8(v);
            state_ops::copy_state(dx0, x0);
            dx0[id_word] ^= u8(1u << id_bit);
            ROUND(x0, 1);
            ROUND(dx0, 1);
            for (int i = 0; i < 16; ++i) weight[k][v] += std::popcount(u8(x0[i] ^ dx0[i]));
            if (weight[k][v] < fewest) fewest = weight[k][v];
        }

    // the first suitable IV byte of every column key, -1 for a strong key
    std::vector<int> suitable(column_keys, -1), strong;
    for (int k = 0; k < column_keys; ++k)
    {
        for (int v = 0; v < 256 && suitable[k] < 0; ++v)
            if (weight[k][v] == fewest) suitable[k] = v;
        if (suitable[k] < 0) strong.push_back(k);
    }

    std::cout << '\n' << report_util::section("Results") << '\n';
    report_util::ParamTable(13)
        .row("Fewest", fewest, " differences after one round")
        .row("Weak keys", column_keys - int(strong.size()), " of ", column_keys)
        .row("Strong keys", strong.size() <= 16 ? string_util::join_indices(strong) : std::to_string(strong.size()));

    std::ofstream out = toy_util::open_output(options);
    out << "{\n  \"key_size_bits\": " << KEY_SIZE_BITS << ",\n  \"column\": " << column
        << ",\n  \"fewest_differences\": " << fewest << ",\n  \"weak_keys\": " << column_keys - int(strong.size())
        << ",\n  \"strong_keys\": " << toy_util::json_list(strong)
        << ",\n  \"suitable_iv\": " << toy_util::json_list(suitable) << "\n}\n";

    std::cout << '\n' << report_util::section("Summary") << '\n';
    report_util::ParamTable(13).row("Elapsed", report_util::format_duration(timer.elapsed()));
    return 0;
}
