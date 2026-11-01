"""Statistical calculations shared by the three ToyChaCha attacks."""
from __future__ import annotations

import math
from statistics import NormalDist


def validate_parameters(alpha: float, p_nd: float) -> None:
    if not math.isfinite(alpha) or alpha <= 0:
        raise ValueError("alpha must be finite and positive (or 'min' where supported)")
    if not math.isfinite(p_nd) or not 0 < p_nd < 0.5:
        raise ValueError("p_nd must be between 0 and 0.5, excluding both endpoints")


def correlation(value: float) -> float:
    if not math.isfinite(value) or not -1 <= value <= 1:
        raise ValueError("correlations must be finite and between -1 and 1")
    return value


def compute_stage_N(alpha: float, fwd_eps: float, bwd_eps: float, p_nd: float) -> float:
    """Eq. 7, before rounding. Zero measured signal cannot define an attack."""
    validate_parameters(alpha, p_nd)
    epsilon = abs(correlation(fwd_eps) * correlation(bwd_eps))
    if epsilon == 0:
        raise ValueError("combined correlation is zero; increase --samples or choose another distinguisher")
    z = NormalDist().inv_cdf(p_nd)
    return ((math.sqrt(alpha * math.log(4)) - z * math.sqrt(1 - epsilon ** 2)) / epsilon) ** 2


def nearest(value: float) -> int:
    if not math.isfinite(value):
        raise ValueError("the estimated sample count is not finite")
    return math.floor(value + 0.5)


def compute_T(N: int, epsilon: float, p_nd: float) -> float:
    validate_parameters(1, p_nd)
    correlation(epsilon)
    if not 1 <= N < 2 ** 64:
        raise ValueError("N must round to a positive integer below 2^64; adjust alpha or the distinguisher")
    return N * (1 + epsilon) / 2 + NormalDist().inv_cdf(p_nd) * math.sqrt(N * (1 - epsilon ** 2)) / 2


def compute_C(m: int, N: int, key_size: int, alpha: float) -> dict[str, float]:
    return {"sig": m + math.log2(N), "pnb": float(key_size - m), "false_alarm": key_size - alpha}


def total_complexity(alpha: float, m: int, fwd_eps: float, bwd_eps: float, key_size: int, p_nd: float) -> float:
    N = nearest(compute_stage_N(alpha, fwd_eps, bwd_eps, p_nd))
    compute_T(N, abs(fwd_eps * bwd_eps), p_nd)  # validate the rounded sample count
    return math.log2(sum(2 ** term for term in compute_C(m, N, key_size, alpha).values()))


def minimise_alpha(m: int, fwd_eps: float, bwd_eps: float, key_size: int, p_nd: float) -> int:
    return min(range(1, key_size + 1), key=lambda a: total_complexity(a, m, fwd_eps, bwd_eps, key_size, p_nd))


def log_binomial_tail(n: int, t: int, p: float) -> float:
    """Natural log of Pr(X >= t), with endpoint handling and no tail underflow.

    Start at the largest term in the tail and sum relative weights in both
    directions. Every relative weight is at most one.
    """
    if n < 0 or not math.isfinite(p) or not 0 <= p <= 1:
        raise ValueError("invalid binomial parameters")
    if t <= 0:
        return 0.0
    if t > n or p == 0:
        return -math.inf
    if p == 1:
        return 0.0
    mode = max(t, min(n, math.floor((n + 1) * p)))
    anchor = (math.lgamma(n + 1) - math.lgamma(mode + 1) - math.lgamma(n - mode + 1)
              + mode * math.log(p) + (n - mode) * math.log1p(-p))
    total = 1.0
    weight = 1.0
    for i in range(mode, t, -1):
        weight *= i * (1 - p) / ((n - i + 1) * p)
        total += weight
        if weight == 0:
            break
    weight = 1.0
    for i in range(mode, n):
        weight *= (n - i) * p / ((i + 1) * (1 - p))
        total += weight
        if weight == 0:
            break
    return min(0.0, anchor + math.log(total))


def binomial_tail(n: int, t: int, p: float) -> float:
    return math.exp(log_binomial_tail(n, t, p))


def log2_binomial_tail(n: int, t: int, p: float) -> float:
    return log_binomial_tail(n, t, p) / math.log(2)


def count_probability(fwd_eps: float, bwd_eps: float, count_value: int) -> float:
    """Use the attack's fixed test direction, even when a key's bias changes sign."""
    if count_value not in (0, 1):
        raise ValueError("count_value must be 0 or 1")
    signed = correlation(fwd_eps) * correlation(bwd_eps)
    return (1 + (signed if count_value == 0 else -signed)) / 2


def success_per_key(N: int, T: int, per_key_fwd_eps: list[float], bwd_eps: float, count_value: int) -> float:
    if not per_key_fwd_eps:
        raise ValueError("per-key correlations cannot be empty")
    return math.fsum(binomial_tail(N, T, count_probability(e, bwd_eps, count_value))
                     for e in per_key_fwd_eps) / len(per_key_fwd_eps)


def joint_success_per_key(stages: list[dict], per_key_fwd_eps: list[list[float]]) -> float:
    if not stages or not per_key_fwd_eps:
        raise ValueError("stages and per-key correlations cannot be empty")
    total = 0.0
    for key in per_key_fwd_eps:
        if len(key) != len(stages):
            raise ValueError("per-key correlations must have one value per stage")
        passes = 1.0
        for stage, e in zip(stages, key):
            passes *= binomial_tail(stage["N"], stage["T"],
                                    count_probability(e, stage["bwd_eps"], stage["count_value"]))
        total += passes
    return total / len(per_key_fwd_eps)
