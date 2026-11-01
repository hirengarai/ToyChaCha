/*
 * ToyChaCha operations (Section 4.1 of the paper)
 * Hiren | NTU Singapore
 * Created: 2022 | Updated: 2026-10-24
 *
 * The structure, names and round numbering of chachaCipher/chacha.hpp, with 8-bit
 * words: the quarterround of Eq. 8 rotates by 4, 3, 2, 1 where ChaCha rotates by
 * 16, 12, 8, 7, so its four ARX groups are ARX4, ARX3, ARX2 and ARX1.
 *
 * Usage: #include "toychacha.hpp"
 */
#pragma once

#include "common_utility/core_types.hpp"

// ---- Constants -----------------------------------------------

constexpr u8 C0 = 0x65;
constexpr u8 C1 = 0x6e;
constexpr u8 C2 = 0x32;
constexpr u8 C3 = 0x74;

// ---- State initialization ------------------------------------
// Constants: x[0..3]. Key: x[4..11]. IV: x[12..15].
// Supply eight key words, repeating the first four for a 32-bit key (the paper's ToyChaCha).

template <class W>
inline void INSERT_KEY(W *x, const W *key)
{
    for (int i = 0; i < 8; ++i) x[i + 4] = key[i];
}

template <class W>
inline void INIT_STATE(W *x, const W *key, const W *iv)
{
    x[0] = C0;
    x[1] = C1;
    x[2] = C2;
    x[3] = C3;
    INSERT_KEY(x, key);
    for (int i = 0; i < 4; ++i) x[i + 12] = iv[i];
}

// W is u8: every word wraps modulo 2^8 by itself, so no explicit reduction is needed.
// OP1(a, b, c, d, true) replaces only that addition with XOR.
// ARX4(..., true) or QUARTERROUND(..., true) replaces all additions in that group.
// Use the same flags in the matching INV_ calls.

// ---- Forward operations --------------------------------------

template <class W>
inline void OP1(W &a, W &b, W &, W &, bool use_xor = false)
{
    if (use_xor) a ^= b;
    else         a += b;
}

template <class W>
inline void OP2(W &a, W &, W &, W &d) { d ^= a; }

template <class W>
inline void OP3(W &, W &, W &, W &d) { d = W(d << 4 | d >> 4); }

template <class W>
inline void OP4(W &, W &, W &c, W &d, bool use_xor = false)
{
    if (use_xor) c ^= d;
    else         c += d;
}

template <class W>
inline void OP5(W &, W &b, W &c, W &) { b ^= c; }

template <class W>
inline void OP6(W &, W &b, W &, W &) { b = W(b << 3 | b >> 5); }

template <class W>
inline void OP7(W &a, W &b, W &, W &, bool use_xor = false)
{
    if (use_xor) a ^= b;
    else         a += b;
}

template <class W>
inline void OP8(W &a, W &, W &, W &d) { d ^= a; }

template <class W>
inline void OP9(W &, W &, W &, W &d) { d = W(d << 2 | d >> 6); }

template <class W>
inline void OP10(W &, W &, W &c, W &d, bool use_xor = false)
{
    if (use_xor) c ^= d;
    else         c += d;
}

template <class W>
inline void OP11(W &, W &b, W &c, W &) { b ^= c; }

template <class W>
inline void OP12(W &, W &b, W &, W &) { b = W(b << 1 | b >> 7); }

// ---- Forward groups ------------------------------------------

template <class W>
inline void ARX4(W &a, W &b, W &c, W &d, bool use_xor = false)
{
    OP1(a, b, c, d, use_xor);
    OP2(a, b, c, d);
    OP3(a, b, c, d);
}

template <class W>
inline void ARX3(W &a, W &b, W &c, W &d, bool use_xor = false)
{
    OP4(a, b, c, d, use_xor);
    OP5(a, b, c, d);
    OP6(a, b, c, d);
}

template <class W>
inline void ARX2(W &a, W &b, W &c, W &d, bool use_xor = false)
{
    OP7(a, b, c, d, use_xor);
    OP8(a, b, c, d);
    OP9(a, b, c, d);
}

template <class W>
inline void ARX1(W &a, W &b, W &c, W &d, bool use_xor = false)
{
    OP10(a, b, c, d, use_xor);
    OP11(a, b, c, d);
    OP12(a, b, c, d);
}

template <class W>
inline void QUARTERROUND(W &a, W &b, W &c, W &d, bool use_xor = false)
{
    ARX4(a, b, c, d, use_xor);
    ARX3(a, b, c, d, use_xor);
    ARX2(a, b, c, d, use_xor);
    ARX1(a, b, c, d, use_xor);
}

// ---- Forward round -------------------------------------------
// One round: odd = columns, even = diagonals. Round numbers start at 1.

template <class W>
inline void ROUND(W *x, int round, bool use_xor = false)
{
    if (round & 1)
    {
        QUARTERROUND(x[0], x[4], x[8], x[12], use_xor);
        QUARTERROUND(x[1], x[5], x[9], x[13], use_xor);
        QUARTERROUND(x[2], x[6], x[10], x[14], use_xor);
        QUARTERROUND(x[3], x[7], x[11], x[15], use_xor);
    }
    else
    {
        QUARTERROUND(x[0], x[5], x[10], x[15], use_xor);
        QUARTERROUND(x[1], x[6], x[11], x[12], use_xor);
        QUARTERROUND(x[2], x[7], x[8], x[13], use_xor);
        QUARTERROUND(x[3], x[4], x[9], x[14], use_xor);
    }
}

// One 0.25-round step: the same ARX group across ALL four tuples.
// E.g. round 3.5 ends after ARX4 and ARX3 of every diagonal in round 4.
// Steps start at zero; this is NOT one complete quarter-round on one tuple.
template <class W>
[[gnu::always_inline]] inline void ROUND_STEP(W *x, int step, bool use_xor = false)
{
    const int diagonal = (step / 4) % 2;
    for (int a = 0; a < 4; ++a)
    {
        const int b = 4 + (a + diagonal) % 4;
        const int c = 8 + (a + 2 * diagonal) % 4;
        const int d = 12 + (a + 3 * diagonal) % 4;
        switch (step % 4)
        {
        case 0: ARX4(x[a], x[b], x[c], x[d], use_xor); break;
        case 1: ARX3(x[a], x[b], x[c], x[d], use_xor); break;
        case 2: ARX2(x[a], x[b], x[c], x[d], use_xor); break;
        case 3: ARX1(x[a], x[b], x[c], x[d], use_xor); break;
        }
    }
}

// ---- Inverse operations --------------------------------------
// INV_OPN undoes OPN. Execute INV_OP12 down to INV_OP1 to undo a quarter-round.

template <class W>
inline void INV_OP1(W &a, W &b, W &, W &, bool use_xor = false)
{
    if (use_xor) a ^= b;
    else         a -= b;
}

template <class W>
inline void INV_OP2(W &a, W &, W &, W &d) { d ^= a; }

template <class W>
inline void INV_OP3(W &, W &, W &, W &d) { d = W(d >> 4 | d << 4); }

template <class W>
inline void INV_OP4(W &, W &, W &c, W &d, bool use_xor = false)
{
    if (use_xor) c ^= d;
    else         c -= d;
}

template <class W>
inline void INV_OP5(W &, W &b, W &c, W &) { b ^= c; }

template <class W>
inline void INV_OP6(W &, W &b, W &, W &) { b = W(b >> 3 | b << 5); }

template <class W>
inline void INV_OP7(W &a, W &b, W &, W &, bool use_xor = false)
{
    if (use_xor) a ^= b;
    else         a -= b;
}

template <class W>
inline void INV_OP8(W &a, W &, W &, W &d) { d ^= a; }

template <class W>
inline void INV_OP9(W &, W &, W &, W &d) { d = W(d >> 2 | d << 6); }

template <class W>
inline void INV_OP10(W &, W &, W &c, W &d, bool use_xor = false)
{
    if (use_xor) c ^= d;
    else         c -= d;
}

template <class W>
inline void INV_OP11(W &, W &b, W &c, W &) { b ^= c; }

template <class W>
inline void INV_OP12(W &, W &b, W &, W &) { b = W(b >> 1 | b << 7); }

// ---- Inverse groups ------------------------------------------

template <class W>
inline void INV_ARX4(W &a, W &b, W &c, W &d, bool use_xor = false)
{
    INV_OP3(a, b, c, d);
    INV_OP2(a, b, c, d);
    INV_OP1(a, b, c, d, use_xor);
}

template <class W>
inline void INV_ARX3(W &a, W &b, W &c, W &d, bool use_xor = false)
{
    INV_OP6(a, b, c, d);
    INV_OP5(a, b, c, d);
    INV_OP4(a, b, c, d, use_xor);
}

template <class W>
inline void INV_ARX2(W &a, W &b, W &c, W &d, bool use_xor = false)
{
    INV_OP9(a, b, c, d);
    INV_OP8(a, b, c, d);
    INV_OP7(a, b, c, d, use_xor);
}

template <class W>
inline void INV_ARX1(W &a, W &b, W &c, W &d, bool use_xor = false)
{
    INV_OP12(a, b, c, d);
    INV_OP11(a, b, c, d);
    INV_OP10(a, b, c, d, use_xor);
}

template <class W>
inline void INV_QUARTERROUND(W &a, W &b, W &c, W &d, bool use_xor = false)
{
    INV_ARX1(a, b, c, d, use_xor);
    INV_ARX2(a, b, c, d, use_xor);
    INV_ARX3(a, b, c, d, use_xor);
    INV_ARX4(a, b, c, d, use_xor);
}

// ---- Inverse round -------------------------------------------
// One round: odd = columns, even = diagonals. Round numbers start at 1.

template <class W>
inline void INV_ROUND(W *x, int round, bool use_xor = false)
{
    if (round & 1)
    {
        INV_QUARTERROUND(x[3], x[7], x[11], x[15], use_xor);
        INV_QUARTERROUND(x[2], x[6], x[10], x[14], use_xor);
        INV_QUARTERROUND(x[1], x[5], x[9], x[13], use_xor);
        INV_QUARTERROUND(x[0], x[4], x[8], x[12], use_xor);
    }
    else
    {
        INV_QUARTERROUND(x[3], x[4], x[9], x[14], use_xor);
        INV_QUARTERROUND(x[2], x[7], x[8], x[13], use_xor);
        INV_QUARTERROUND(x[1], x[6], x[11], x[12], use_xor);
        INV_QUARTERROUND(x[0], x[5], x[10], x[15], use_xor);
    }
}

// One 0.25-round step: the same ARX group across ALL four tuples.
// E.g. round 3.5 ends after ARX4 and ARX3 of every diagonal in round 4.
// Steps start at zero; this is NOT one complete quarter-round on one tuple.
template <class W>
[[gnu::always_inline]] inline void INV_ROUND_STEP(W *x, int step, bool use_xor = false)
{
    const int diagonal = (step / 4) % 2;
    for (int a = 3; a >= 0; --a)
    {
        const int b = 4 + (a + diagonal) % 4;
        const int c = 8 + (a + 2 * diagonal) % 4;
        const int d = 12 + (a + 3 * diagonal) % 4;
        switch (step % 4)
        {
        case 0: INV_ARX4(x[a], x[b], x[c], x[d], use_xor); break;
        case 1: INV_ARX3(x[a], x[b], x[c], x[d], use_xor); break;
        case 2: INV_ARX2(x[a], x[b], x[c], x[d], use_xor); break;
        case 3: INV_ARX1(x[a], x[b], x[c], x[d], use_xor); break;
        }
    }
}
