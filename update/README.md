# A recipe for a key recovery attack

We use ToyChaCha to see each part of an attack working. Start with `aumasson/`:
it attacks 3.5 rounds using a distinguisher on the first 2 rounds. The cipher is
in [toychacha.hpp](toychacha.hpp).

You need Python 3.8 or newer and a C++20 compiler with `std::format` support.
There are no Python packages to install. The scripts use `g++` by default; set
`CXX` to use another compiler. Run the commands below from the main repo folder.

First do the preparation:

```sh
python3 update/aumasson/run.py --demo --step offline --output update/aumasson/results/recipe
```

This runs steps 1–4 in order. We generate keys ourselves during preparation, so
we can measure what happens when a guess is right or wrong. `--demo` uses fewer
samples; leave it out for the normal settings. If you already ran the example
from the main README, add `--resume` to reuse its results.

1. **We need a distinguisher, so we search for one.**

   Take two IVs that differ in one bit, use the same key, and run 2 rounds.
   Look for an output bit whose difference is 0 or 1 more often than half the time.
   That bias gives us a test we can later use to judge key guesses.

   [dist_search.cpp](aumasson/offline/dist_search.cpp) searches the input/output
   pairs and measures their forward correlation, `fwd_eps` (ε_d). A larger absolute
   value means a stronger bias. Its results go into `dist_search.json`.

   This recipe uses the paper's pair: input word 13, bit 0 → output word 1, bit 6.
   The program also lists stronger pairs; it keeps the configured pair for the
   remaining steps. Words and bits are numbered from zero.

2. **We need fewer bits to guess, so we search for PNBs.**

   The keystream adds the initial state back after the cipher rounds. To work
   backwards, we subtract a guessed initial state and undo the last 1.5 rounds.
   [pnb_search.cpp](aumasson/offline/pnb_search.cpp) changes one key bit in that
   guess and checks how often the 2-round output difference stays the same.

   Bits with a neutrality score above the chosen threshold become probabilistic
   neutral bits, or PNBs. We can try random values for them while guessing the
   other bits, called significant bits. PNBs can still change the test result.
   The scores and both bit lists go into `pnb_search.json`.

3. **We need to know whether those PNBs work together.**

   [bwd_corr.cpp](aumasson/offline/bwd_corr.cpp) keeps the significant bits correct
   and randomises all the PNBs for each sample. It measures agreement between the
   true forward difference and the difference obtained by going backwards.
   This is the backward correlation, `bwd_eps` (ε_a).

   It also measures the combined correlation directly. These measurements go into
   `bwd_corr.json`. The next step compares the direct measurement with the model
   approximation, ε_d × ε_a.

4. **We need a sample count and a rule for accepting guesses.**

   [complexity.py](aumasson/offline/complexity.py) uses those measurements to
   calculate `N`, the number of keystream pairs to collect, and `T`, the count a
   guess must reach to pass the test. It also estimates the work and success rate.
   These values go into `complexity.json`. The formulae shared by the attacks are
   in [statistics_util.py](statistics_util.py).

5. **Now we try to recover a key.**

   Run the attack using the preparation we just finished:

   ```sh
   python3 update/aumasson/run.py --step online --keys 1 --output update/aumasson/results/recipe
   ```

   [key_recovery.cpp](aumasson/online/key_recovery.cpp) collects `N` keystream pairs
   from a generated target key. For each guess of the significant bits, it
   randomises the PNBs and runs the backward test. It counts the output difference
   favoured by the measured correlation.

   If the count reaches `T`, it searches every value of the PNBs and checks each
   complete candidate against the keystream. A wrong significant-bit guess that
   passes the threshold is a false alarm: it causes extra search work.
   The program prints the original key and whether it recovered it, and saves
   the counters in `key_recovery.json`.

6. **We check whether the theory predicted the experiment.**

   [report.py](aumasson/online/report.py) runs automatically after key recovery.
   Open `report.md` in the output folder to compare the estimated work and success
   rate with the measurements. The false-alarm target and success estimates depend
   on model assumptions; the experiment lets us check them.

To measure success over more keys, reuse the preparation and replace the online run:

```sh
python3 update/aumasson/run.py --step online --keys 64 --jobs 4 --overwrite --output update/aumasson/results/recipe
```

Here, `--keys 64` tries 64 random keys and `--jobs 4` runs four processes.

The other attacks change the recipe in these ways:

- **Maitra's chosen-IV attack** starts with
  [weak_key_search.cpp](maitra/offline/weak_key_search.cpp). It searches for IV
  bytes that give the fewest differences after one round, for each column-key
  value. That gives the suitable-IV table in `weak_key_search.json`. The later
  steps use those IVs, and recovery is measured on keys with a suitable IV.
- **The multi-step attack** uses three input/output pairs. Its
  [pnb_search.cpp](multi_step/offline/pnb_search.cpp) divides significant bits
  into sets `S1`, `S2`, and `S3`. Recover `S1`, keep it fixed while guessing `S2`,
  then keep both fixed while guessing `S3`. Finally search the remaining bits.

Try their complete recipes with:

```sh
python3 update/maitra/run.py --demo --output update/maitra/results/recipe
python3 update/multi_step/run.py --demo --output update/multi_step/results/recipe
```

For a first experiment, change the PNB threshold and compare the two reports:

```sh
python3 update/aumasson/run.py --demo --threshold 0.5 --output update/aumasson/results/threshold_05
```

A higher threshold leaves fewer PNBs: more significant bits to guess up front,
and fewer bits to search after a guess passes. Check what happens to `N`, the
false alarms, and the total work.

Use a new output folder when changing attack settings. The scripts pass each
step's results to the next through a generated `control_panel.hpp`; leave the
generated files as they are. Add `--resume` to continue a stopped run, or to reuse
finished results. An interrupted online attack starts that part again.
For all available settings, run `python3 update/aumasson/run.py --help`.

## Theory vs experiment

These are the saved 32-bit experiments: seed 1, 2^22 offline samples per estimate,
and 32,768 keys per attack. They use the larger runs, rather than the small demo.
[AFK+08] is the Aumasson attack; [Mai16] is the Maitra attack. Costs are written
as powers of two, and success probability is the fraction of keys recovered.

The saved runs predate the recent counter fixes. A new run's `report.md` uses
the corrected counters.

Table 3, 3.5 rounds:

| | [AFK+08] paper | [AFK+08] here | [Mai16] paper | [Mai16] here |
|---|---|---|---|---|
| data N | 378 | 378 | 185 | 182 |
| significant bits, theory | 2^24.56 | 2^24.56 | 2^24.53 | 2^24.51 |
| significant bits, experiment | 2^23.56 | 2^23.56 | 2^23.47 | 2^23.47 |
| false alarm, theory | 2^21 | 2^21 | 2^21 | 2^21 |
| false alarm, experiment | 2^18.18 | 2^18.16 | 2^17.59 | 2^17.78 |
| PNBs, theory | 2^16 | 2^16 | 2^15 | 2^15 |
| PNBs, experiment | 2^15.01 | 2^15.00 | 2^13.99 | 2^14.00 |
| total, theory | 2^24.67 | 2^24.68 | 2^24.65 | 2^24.63 |
| total, experiment | 2^23.60 | 2^23.60 | 2^23.50 | 2^23.50 |
| success probability | 0.9981 | 0.9984 | 0.9971 | 0.9961 |
| Pr_fa | 0.00034 | 0.00033 | 0.00015 | 0.00017 |

Table 4, 3 rounds:

| | single paper | single here | multiple paper | multiple here |
|---|---|---|---|---|
| data N | 95 | 93 | 94 | 93 per stage |
| recover S1 (and S2, S3), theory | 2^14.56 | 2^14.54 | 2^14.56 each | 2^14.54 each |
| recover S1 (and S2, S3), experiment | 2^13.51 | 2^13.57 | 2^13.51, 2^13.51, 2^13.5 | 2^13.58, 2^13.55, 2^13.53 |
| false alarms, experiment | 0 | 0 | 0 | 1 (stage 3, in 4.2 million guesses) |
| PNBs, theory | 2^24 | 2^24 | 2^8 | 2^8 |
| PNBs, experiment | 2^23.01 | 2^22.99 | 2^6.95 | 2^6.97 |
| total, [AFK+08] formula | 2^14.56 | 2^14.54 | | |
| total, [DGSS22] formula | 2^24 | 2^24 | 2^16.15 | 2^16.13 |
| total, experiment | 2^23.01 | 2^22.99 | 2^15.1 | 2^15.15 |
| success probability | not given | 0.9912 | not given | 0.9725 |
