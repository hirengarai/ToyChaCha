/*
 * Filename: string_ops.hpp
 *
 * String <-> state conversions for hex / binary representations of cipher
 * state arrays. Used to parse OCP / autoguess output and to render results.
 */

#pragma once

#include <charconv>
#include <concepts>
#include <format>
#include <stdexcept>
#include <string>
#include <string_view>

namespace string_util
{
    // ---------- list rendering ----------

    /// Joins a range into "{a, b, c}", rendering each element with `fmt`.
    template <typename Range, typename Fmt>
    inline std::string join(const Range &r,
                            Fmt fmt,
                            std::string_view sep   = ", ",
                            std::string_view open  = "{",
                            std::string_view close = "}")
    {
        std::string out(open);
        bool first = true;
        for (const auto &e : r)
        {
            if (!first)
                out += sep;
            out += fmt(e);
            first = false;
        }
        out += close;
        return out;
    }

    /// Renders a (word, bit) coordinate list as "{(2,0), (6,7)}".
    template <typename Range>
    inline std::string join_bitpos(const Range &r)
    {
        return join(r, [](const auto &p)
                    { return "(" + std::to_string(p.first) + "," + std::to_string(p.second) + ")"; });
    }

    /// Renders an index list as "{1, 2, 3}".
    template <typename Range>
    inline std::string join_indices(const Range &r)
    {
        return join(r, [](const auto &v) { return std::to_string(v); });
    }

    // ---------- state conversions ----------

    /// Converts a hex or binary string view into an array of N unsigned state words.
    template <std::unsigned_integral T, std::size_t N>
    void string_to_state(std::string_view s, T (&out)[N], bool hex_flag = true)
    {
        constexpr std::size_t bits = sizeof(T) * 8;
        constexpr std::size_t hex_ch = bits / 4;

        if (hex_flag)
        {
            if (s.starts_with("0x") || s.starts_with("0X"))
                s.remove_prefix(2);
            if (s.size() != hex_ch * N)
                throw std::runtime_error("Hex length mismatch");

            for (std::size_t i = 0; i < N; i++)
            {
                std::string_view chunk = s.substr(i * hex_ch, hex_ch);
                if constexpr (sizeof(T) <= 8)
                {
                    std::from_chars(chunk.data(), chunk.data() + chunk.size(), out[i], 16);
                }
                else
                {
                    T value = 0;
                    for (char c : chunk)
                    {
                        value <<= 4;
                        if (c >= '0' && c <= '9')
                            value |= (c - '0');
                        else if (c >= 'a' && c <= 'f')
                            value |= (c - 'a' + 10);
                        else if (c >= 'A' && c <= 'F')
                            value |= (c - 'A' + 10);
                        else
                            throw std::runtime_error("Invalid hex char");
                    }
                    out[i] = value;
                }
            }
            return;
        }

        if (s.starts_with("0b") || s.starts_with("0B"))
            s.remove_prefix(2);
        if (s.size() != bits * N)
            throw std::runtime_error("Binary length mismatch");

        for (std::size_t i = 0; i < N; i++)
        {
            std::string_view chunk = s.substr(i * bits, bits);
            if constexpr (sizeof(T) <= 8)
            {
                std::from_chars(chunk.data(), chunk.data() + chunk.size(), out[i], 2);
            }
            else
            {
                T value = 0;
                for (char c : chunk)
                {
                    value <<= 1;
                    if (c == '1')
                        value |= 1;
                    else if (c != '0')
                        throw std::runtime_error("Invalid binary char");
                }
                out[i] = value;
            }
        }
    }

    /// Auto-detects hex or binary prefix and converts to state array.
    template <std::unsigned_integral T, std::size_t N>
    void string_to_state_auto(std::string_view str, T (&out)[N])
    {
        if (str.starts_with("0x") || str.starts_with("0X"))
            return string_to_state(str, out, true);
        if (str.starts_with("0b") || str.starts_with("0B"))
            return string_to_state(str, out, false);

        throw std::runtime_error("Cannot infer format; prefix with 0x or 0b");
    }

    /// Converts an array of unsigned words into one hex string using C++20 std::format.
    template <std::unsigned_integral T>
    std::string state_to_string(const T *x, std::size_t count = 16)
    {
        std::string out = "0x";
        for (std::size_t i = 0; i < count; ++i)
        {
            if constexpr (sizeof(T) == 4)
            {
                out += std::format("{:08x}", x[i]);
            }
            else if constexpr (sizeof(T) == 8)
            {
                out += std::format("{:016x}", x[i]);
            }
            else
            {
                out += std::format("{:x}", x[i]);
            }
        }
        return out;
    }
}
