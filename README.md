# ToyChaCha

ToyChaCha is a small version of ChaCha. Its words are 8 bits and its usual key is
32 bits, so we can try a key recovery attack and see how the theory holds up.
The [paper](21_dey_garai_maitra.pdf) explains the attacks.

The code in `update/` follows this recipe:

1. Find an input difference that gives a biased output difference: a distinguisher.
2. Find key bits we can randomise while guessing the others: the PNBs.
3. Measure how well the distinguisher survives when those PNBs are random.
4. Calculate how much data we need and the threshold for accepting a guess.
5. Guess the significant bits, then search the PNBs to recover the whole key.
6. Compare the predicted cost and success rate with what actually happened.

Follow the [recipe in update/README.md](update/README.md). It explains why we need
each step, which file does it, and what to look for in its output.

You need Python 3.8 or newer and a C++20 compiler with `std::format` support.
From this folder, this command runs a small example of the whole recipe:

```sh
python3 update/aumasson/run.py --demo --output update/aumasson/results/recipe
```

The script builds the C++ code for you. The results and `report.md` go into
`update/aumasson/results/recipe/`. If you have already run this command, add
`--resume` to reuse its results.

The original C++ programs are still in the main folder. The recipe uses the
reorganised code in `update/`.
