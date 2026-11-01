/*
 * ToyChaCha experiment helpers: keys, IVs, key bits, command line and JSON output
 * Hiren | NTU Singapore
 * Created: 2026 | Updated: 2026-10-24
 *
 * Usage: #include "toy_util.hpp"
 */
#pragma once

#include "common_utility/core_types.hpp"
#include "common_utility/random_util.hpp"

#include <charconv>
#include <cstdlib>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <initializer_list>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace toy_util
{
    using Rng = random_util::Xoshiro256StarStar;

    [[noreturn]] inline void fail(const std::string &message)
    {
        std::cerr << "error: " << message << '\n';
        std::exit(1);
    }

    /// 2^64 cannot be represented as the exclusive end of a u64 loop.
    inline u64 search_values(std::size_t bits)
    {
        if (bits >= 64) fail("a search set has 64 or more bits; choose another neutrality threshold (maximum 63)");
        return u64{1} << bits;
    }

    template <class Positions>
    inline void validate_positions(const Positions &inputs, const Positions &outputs, bool single = false)
    {
        if (inputs.empty() || outputs.empty() || (single && (inputs.size() != 1 || outputs.size() != 1)))
            fail("nonempty input/output positions are required (one bit each for the chosen-IV attack)");
        for (const auto &[word, bit] : inputs)
            if (word < 12 || word > 15 || bit > 7) fail("input positions require IV words 12..15 and bits 0..7");
        for (const auto &[word, bit] : outputs)
            if (word > 15 || bit > 7) fail("output positions require words 0..15 and bits 0..7");
    }

    inline void validate_partition(int key_bits, std::initializer_list<std::vector<u16>> groups)
    {
        std::vector<bool> seen(key_bits, false);
        for (const auto &bits : groups)
            for (const auto bit : bits)
            {
                if (bit >= key_bits || seen[bit]) fail("search sets must contain each key bit exactly once");
                seen[bit] = true;
            }
        for (const bool present : seen)
            if (!present) fail("search sets must contain each key bit exactly once");
    }

    template <std::size_t Size>
    inline void validate_suitable_iv(const int (&values)[Size], int key_bits)
    {
        if (Size != (key_bits == 32 ? 256 : 65536)) fail("suitable-IV table has the wrong size");
        bool any = false;
        for (const int iv : values)
        {
            if (iv < -1 || iv > 255) fail("suitable-IV entries must be -1 or a byte");
            any |= iv >= 0;
        }
        if (!any) fail("no weak column key has a suitable IV");
    }

    // ---- Keys and IVs --------------------------------------------
    // A 32-bit key fills key words 0..3 and repeats them in 4..7 (the paper's ToyChaCha);
    // a 64-bit key fills all eight key words.

    /// One uniform byte: the top bits of xoshiro256** are its strongest.
    inline u8 random_byte(Rng &rng) { return static_cast<u8>(rng() >> 56); }

    inline void random_key(u8 *key, int key_size_bits, Rng &rng)
    {
        for (int i = 0; i < key_size_bits / 8; ++i) key[i] = random_byte(rng);
        if (key_size_bits == 32)
            for (int i = 0; i < 4; ++i) key[i + 4] = key[i];
    }

    inline void random_iv(u8 *iv, Rng &rng)
    {
        for (int i = 0; i < 4; ++i) iv[i] = random_byte(rng);
    }

    // ---- Key bits ------------------------------------------------
    // Key bit b sits in key word b / 8 at bit b % 8; a 32-bit key also has it in word b / 8 + 4.

    inline u8 key_bit(const u8 *key, int bit) { return (key[bit / 8] >> (bit % 8)) & 1; }

    inline void set_key_bit(u8 *key, int bit, u8 value, int key_size_bits)
    {
        const u8 mask = u8(1u << (bit % 8));
        key[bit / 8] = u8(value ? key[bit / 8] | mask : key[bit / 8] & ~mask);
        if (key_size_bits == 32) key[bit / 8 + 4] = key[bit / 8];
    }

    inline void flip_key_bit(u8 *key, int bit, int key_size_bits)
    {
        set_key_bit(key, bit, key_bit(key, bit) ^ 1, key_size_bits);
    }

    /// Writes `value` into the listed key bits: bit j of value goes to bits[size - 1 - j].
    inline void set_key_bits(u8 *key, const std::vector<u16> &bits, u64 value, int key_size_bits)
    {
        for (std::size_t j = 0; j < bits.size(); ++j)
            set_key_bit(key, bits[bits.size() - 1 - j], u8((value >> j) & 1), key_size_bits);
    }

    /// The value of the listed key bits, in the order set_key_bits uses.
    inline u64 get_key_bits(const u8 *key, const std::vector<u16> &bits)
    {
        u64 value = 0;
        for (std::size_t j = 0; j < bits.size(); ++j)
            value |= u64{key_bit(key, bits[bits.size() - 1 - j])} << j;
        return value;
    }

    // ---- Key words of one column ---------------------------------
    // Column c of the state holds key words c and c + 4. For a 32-bit key they are the same
    // byte, so the column key is one byte; for a 64-bit key it is two bytes.

    inline int column_key_values(int key_size_bits) { return key_size_bits == 32 ? 1 << 8 : 1 << 16; }

    inline int column_key(const u8 *key, int column, int key_size_bits)
    {
        return key_size_bits == 32 ? key[column] : key[column] | key[column + 4] << 8;
    }

    inline void set_column_key(u8 *key, int column, int value, int key_size_bits)
    {
        key[column] = u8(value & 0xff);
        key[column + 4] = key_size_bits == 32 ? key[column] : u8(value >> 8);
    }

    /// The key bits of column c, byte by byte with the high bit first (the paper's order).
    inline std::vector<u16> column_key_bits(int column, int key_size_bits)
    {
        std::vector<u16> bits;
        for (int word : {column, column + 4})
        {
            if (word >= key_size_bits / 8) break;
            for (int bit = 8 * word + 7; bit >= 8 * word; --bit) bits.push_back(u16(bit));
        }
        return bits;
    }

    // ---- Command line --------------------------------------------
    // run.py passes these; every other setting is in control_panel.hpp.

    struct Options
    {
        u64 seed = 1;
        u64 samples = 1ULL << 20; // offline programs: samples per estimate
        u64 keys = 1;             // key_recovery: keys to attack
        u64 spread_keys = 4096;   // dist_search: keys in the per-key estimate
        u64 spread_ivs = 4096;    // dist_search: IVs per key in that estimate
        std::string out;          // the JSON results
    };

    inline u64 read_number(std::string_view text)
    {
        u64 value = 0;
        const auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), value);
        if (error != std::errc{} || end != text.data() + text.size())
            throw std::invalid_argument("Expected a number: " + std::string(text));
        return value;
    }

    inline Options parse_options(int argc, char **argv)
    {
        Options options;
        try
        {
            for (int i = 1; i < argc; ++i)
            {
                const std::string_view arg = argv[i];
                const bool has_value = i + 1 < argc;
                if (arg == "--seed" && has_value) options.seed = read_number(argv[++i]);
                else if (arg == "--samples" && has_value) options.samples = read_number(argv[++i]);
                else if (arg == "--keys" && has_value) options.keys = read_number(argv[++i]);
                else if (arg == "--spread-keys" && has_value) options.spread_keys = read_number(argv[++i]);
                else if (arg == "--spread-ivs" && has_value) options.spread_ivs = read_number(argv[++i]);
                else if (arg == "--out" && has_value) options.out = argv[++i];
                else
                {
                    std::cerr << "Usage: " << argv[0] << " [--seed S] [--samples N] [--keys K] "
                              << "[--spread-keys K] [--spread-ivs N] --out FILE\n"
                              << "Other settings are in control_panel.hpp.\n";
                    std::exit(arg == "--help" ? 0 : 1);
                }
            }
        }
        catch (const std::invalid_argument &error)
        {
            fail(error.what());
        }
        if (options.samples == 0 || options.keys == 0 || options.spread_keys == 0 || options.spread_ivs == 0)
            fail("sample, key and per-key estimate counts must be positive");
        if (options.out.empty())
        {
            std::cerr << "Missing --out FILE.\n";
            std::exit(1);
        }
        return options;
    }

    // ---- JSON output ---------------------------------------------

    inline std::ofstream open_output(const Options &options)
    {
        std::ofstream out(options.out);
        if (!out)
        {
            std::cerr << "Could not write " << options.out << '\n';
            std::exit(1);
        }
        out << std::setprecision(8);
        return out;
    }

    /// "[a, b, c]" with the stream's precision.
    template <class Range>
    inline std::string json_list(const Range &values)
    {
        std::ostringstream text;
        text << std::setprecision(8) << '[';
        bool first = true;
        for (const auto &v : values)
        {
            text << (first ? "" : ", ") << +v;
            first = false;
        }
        text << ']';
        return text.str();
    }
}
