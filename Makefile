# Toy-ChaCha-32 key recovery attacks.
# Dey, Garai, Maitra -- "Cryptanalysis of Reduced Round ChaCha", ToSC 2023(1), Section 4.
#
#   make                          build everything
#   ./aumassonattack --seed 1     one key recovery, reproducible
#   ./aumassoncomplexity --keys 32768   averages of Table 3 over 2^15 keys
#   make clean

CXX      ?= g++
CXXFLAGS ?= -std=c++17 -O2 -Wall -Wextra

ATTACKS    = aumassonattack chosenivattack singleidodattack multipleidodattack
COMPLEXITY = aumassoncomplexity chosenivcomplexity singleidodcomplexity multipleidodcomplexity
PROGRAMS   = $(ATTACKS) $(COMPLEXITY) sagemath

all: $(PROGRAMS)

$(ATTACKS) $(COMPLEXITY): %: %.cpp chacha.h
	$(CXX) $(CXXFLAGS) -o $@ $<

sagemath: sagemath.cpp
	$(CXX) $(CXXFLAGS) -o $@ $<

clean:
	rm -f $(PROGRAMS)

.PHONY: all clean
