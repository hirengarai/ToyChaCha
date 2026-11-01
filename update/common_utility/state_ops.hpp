/*
 * Filename: state_ops.hpp
 *
 * Operations on cipher state arrays: range copy, compare, flip, and other
 * primitives shared across forward / backward / analysis paths.
 */

#pragma once

#include <algorithm>
#include <cstring>

namespace state_ops
{
    // Arithmetic helpers accept unsigned words or vectors of unsigned lanes.

    /// Copies words in the half-open range [start_idx, end_idx) from src to dst.
    template <typename T>
    inline void copy_state(T *__restrict dst, const T *__restrict src, std::size_t start_idx = 0, std::size_t end_idx = 16)
    {
        std::memcpy(dst + start_idx, src + start_idx, (end_idx - start_idx) * sizeof(T));
    }

    /// XOR two state slices with SIMD acceleration.
    template <typename T>
    inline void xor_state(const T *__restrict x, const T *__restrict x1, T *__restrict output, std::size_t count = 16)
    {
        for (std::size_t i = 0; i < count; ++i)
        {
            output[i] = x[i] ^ x1[i];
        }
    }

    /// Adds two states modulo 2^word_size with SIMD acceleration.
    template <typename T>
    inline void add_state(const T *__restrict x, const T *__restrict x1, T *__restrict z, std::size_t count = 16)
    {
        for (std::size_t i = 0; i < count; ++i)
        {
            z[i] = x[i] + x1[i];
        }
    }

    /// Subtracts two states modulo 2^word_size with SIMD acceleration.
    template <typename T>
    inline void subtract_state(const T *__restrict x, const T *__restrict x1, T *__restrict z, std::size_t count = 16)
    {
        for (std::size_t i = 0; i < count; ++i)
        {
            z[i] = x[i] - x1[i];
        }
    }

    /// Fills the slice [start_idx, end_idx) of the state array with a specific value.
    template <typename T>
    inline void set_state(T *__restrict x, std::size_t start_idx = 0, std::size_t end_idx = 16, T value = 0)
    {
        std::fill(x + start_idx, x + end_idx, value);
    }
}
