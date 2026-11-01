/*
 * Filename: random_util.hpp
 *
 * Thread-local Xoshiro256** PRNG plus typed random_number<T>() helpers
 * for unsigned-integer state and key initialization.
 */

#pragma once

#include <array>
#include <bit>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <random>

namespace random_util
{

    /// Xoshiro256** PRNG implementation
    /// https://prng.di.unimi.it/xoshiro256starstar.c
    /// Extremely fast, non-linear
    struct Xoshiro256StarStar
    {
        using result_type = std::uint64_t;
        std::array<std::uint64_t, 4> s_;

        Xoshiro256StarStar()
        {
            std::random_device rd;
            // Seed 64 bits of entropy. We combine two 32-bit calls just in case
            // the OS random_device is only providing 32 bits natively.
            seed((static_cast<std::uint64_t>(rd()) << 32) | rd());
        }

        /// Explicit seeds make experiments reproducible.
        explicit Xoshiro256StarStar(result_type seed_value)
        {
            seed(seed_value);
        }

        void seed(result_type seed_value)
        {
            std::uint64_t sm_state = seed_value;
            // SplitMix64 algorithm to safely populate the 4 state variables
            for (int i = 0; i < 4; ++i)
            {
                sm_state += 0x9e3779b97f4a7c15;
                std::uint64_t z = sm_state;
                z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9;
                z = (z ^ (z >> 27)) * 0x94d049bb133111eb;
                s_[i] = z ^ (z >> 31);
            }
        }

        static constexpr result_type min() { return std::numeric_limits<result_type>::min(); }
        static constexpr result_type max() { return std::numeric_limits<result_type>::max(); }

        inline result_type operator()()
        {
            const std::uint64_t result = std::rotl(s_[1] * 5, 7) * 9;
            const std::uint64_t t = s_[1] << 17;

            s_[2] ^= s_[0];
            s_[3] ^= s_[1];
            s_[1] ^= s_[2];
            s_[0] ^= s_[3];

            s_[2] ^= t;
            s_[3] = std::rotl(s_[3], 45);

            return result;
        }
    };

    /// Fill a SIMD vector of unsigned 32-bit lanes from an explicit generator.
    template <class V>
    inline V random_word(Xoshiro256StarStar &rng)
    {
        V value{};
        static_assert(sizeof(value[0]) == sizeof(std::uint32_t));
        for (std::size_t lane = 0; lane < sizeof(V) / sizeof(value[0]); ++lane)
            value[lane] = static_cast<std::uint32_t>(rng());
        return value;
    }

    // Thread-local instances to prevent locking contention during multi-threading
    inline thread_local Xoshiro256StarStar gen_xo{};
    inline thread_local std::mt19937_64 gen_mt{std::random_device{}()};

    // ---------- primary api: defaults to xoshiro256** ---------

    template <std::integral T>
    inline T random_number(T min = 0, T max = std::numeric_limits<T>::max())
    {
        std::uniform_int_distribution<T> dis(min, max);
        return dis(gen_xo);
    }

    inline bool random_boolean()
    {
        std::bernoulli_distribution dis(0.5);
        return dis(gen_xo);
    }

    // ---------- fallback api: mersenne twister ---------

    template <std::integral T>
    inline T random_number_mt(T min = 0, T max = std::numeric_limits<T>::max())
    {
        std::uniform_int_distribution<T> dis(min, max);
        return dis(gen_mt);
    }

    inline bool random_boolean_mt()
    {
        std::bernoulli_distribution dis(0.5);
        return dis(gen_mt);
    }
}
