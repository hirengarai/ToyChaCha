// Cross-check the reorganized cipher against the original implementation.
#include "../toychacha.hpp"
#include "../toy_util.hpp"
#include "../../chacha.h"
#include <algorithm>
#include <array>
#include <cassert>

int main()
{
    toy_util::Rng rng(7341);
    for (int trial = 0; trial < 10000; ++trial)
    {
        std::array<u8, 16> initial, steps, rounds;
        std::array<ul, 16> legacy;
        for (int i = 0; i < 16; ++i) legacy[i] = initial[i] = toy_util::random_byte(rng);
        steps = rounds = initial;
        for (int r = 1; r <= 8; ++r)
        {
            ROUND(rounds.data(), r);
            FWRound(legacy.data(), r);
            for (int s = (r - 1) * 4; s < r * 4; ++s) ROUND_STEP(steps.data(), s);
            assert(steps == rounds);
            for (int i = 0; i < 16; ++i) assert(legacy[i] == rounds[i]);
        }
        for (int r = 8; r >= 1; --r) INV_ROUND(rounds.data(), r);
        for (int s = 31; s >= 0; --s) INV_ROUND_STEP(steps.data(), s);
        assert(rounds == initial && steps == initial);
        for (int r = 1; r <= 8; ++r)
        {
            ROUND(rounds.data(), r, true);
            for (int s = (r - 1) * 4; s < r * 4; ++s) ROUND_STEP(steps.data(), s, true);
            assert(steps == rounds);
        }
        for (int r = 8; r >= 1; --r) INV_ROUND(rounds.data(), r, true);
        for (int s = 31; s >= 0; --s) INV_ROUND_STEP(steps.data(), s, true);
        assert(rounds == initial && steps == initial);
        for (const int key_bits : {32, 64})
        {
            u8 key[8], restored[8]{};
            toy_util::random_key(key, key_bits, rng);
            std::vector<u16> bits;
            for (int bit = key_bits - 1; bit >= 0; --bit) bits.push_back(bit);
            toy_util::set_key_bits(restored, bits, toy_util::get_key_bits(key, bits), key_bits);
            assert(std::equal(key, key + 8, restored));
        }
    }
}
