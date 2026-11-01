/*
 * Filename: core_types.hpp
 *
 * Project-wide fixed-width integer aliases (u8, u16, u32, u64, ull, longd).
 * Included by every other utility and cipher header.
 */

#pragma once

#include <cstdint>

using ull = unsigned long long;
using longd = long double;

// Fixed-width integer aliases
using u8 = std::uint8_t;
using u16 = std::uint16_t;
using u32 = std::uint32_t;
using u64 = std::uint64_t;
