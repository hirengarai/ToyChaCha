// the complexity finding of multibit attack program in the 8 bit Toy-ChaCha-32 cipher
// (ID - OD)_1 = ((13,0) - (1,6))
// (ID - OD)_2 = ((14,0) - (2,6))
// (ID - OD)_3 = ((15,0) - (3,6))
// 3 round attack
// 2 round distinguisher

// command to execute the prog 👇
// g++ multipleidodcomplexity.cpp && ./a.out

#include <ctime>     // to use time
#include <iomanip>   // decimal numbers upto certain places
#include <chrono>
#include "chacha.h"

int IDword_1 = 13, IDbit_1 = 0; // input difference
int ODword_1 = 1, ODbit_1 = 6; // output difference
int IDword_2 = 14, IDbit_2 = 0; // input difference
int ODword_2 = 2, ODbit_2 = 6; // output difference
int IDword_3 = 15, IDbit_3 = 0; // input difference
int ODword_3 = 3, ODbit_3 = 6; // output difference
const ul N = 94, T = 84; // N = number of samples, T = threshold

ul SIG1[] = { 15, 14, 13, 12, 11, 10, 9, 8 };
ul PNB1[] = { 7,6,5,4,3,2,1,0, 23, 22, 21, 20, 19, 18, 17, 16,  31, 30, 29, 28, 27, 26, 25, 24 };

ul SIG2[] = { 15, 14, 13, 12, 11, 10, 9, 8,23, 22, 21, 20, 19, 18, 17, 16 };
ul PNB2[] = { 7,6,5,4,3,2,1,0,31, 30, 29, 28, 27, 26, 25, 24 };

ul SIG3[] = { 15, 14, 13, 12, 11, 10, 9, 8,23, 22, 21, 20, 19, 18, 17, 16,31, 30, 29, 28, 27, 26, 25, 24 };
ul PNB3[] = { 7,6,5,4,3,2,1,0 };

ul SIG1_COUNT = sizeof(SIG1) / sizeof(SIG1[0]);
ul SIG2_COUNT = sizeof(SIG2) / sizeof(SIG2[0]);
ul SIG3_COUNT = sizeof(SIG3) / sizeof(SIG3[0]);
ul PNB1_COUNT = sizeof(PNB1) / sizeof(PNB1[0]);
ul PNB2_COUNT = sizeof(PNB2) / sizeof(PNB2[0]);
ul PNB3_COUNT = sizeof(PNB3) / sizeof(PNB3[0]);

ul totalSIG = pow(2, SIG1_COUNT);
ul totalPNB1 = pow(2, PNB1_COUNT);
ul totalPNB2 = pow(2, PNB2_COUNT);
ul totalPNB3 = pow(2, PNB3_COUNT);

ul guessKey[8], zeroState[16], DzeroState[16], guesState[16], z[16], Dz[16], DiffState[16], bigZ[16], storedGuesState[16], storedIV[N][16], DstoredIV[N][16], keyst[N][16], Dkeyst[N][16], bacwrdBit, sigGuess, pnbRandom, pnbGuess, WORD, BIT, sampleLoop, guesS;

double sampleKeySize = pow(2, 5);  // change accrodingly

vector <double>VfirstCompl(0);
vector <double>VsecondCompl(0);
vector <double>VthirdCompl(0);
vector <double>VfourthCompl(0);
vector <double>VtotalTime(0);

double  firstCompl, secondCompl, thirdCompl, fourthCompl;

// generateKey from significant and pnb part of the key
void generateKey(ul sig, ul pnb, ul* key, ul* PNB, ul PNB_COUNT, ul* SIG, ul SIG_COUNT)
{
  ul word, bit, pt;
  ReSetState(key, 8);

  // pnb part insertion
  for (int j = 0; j < PNB_COUNT; ++j)
  {
    word = (PNB[PNB_COUNT - 1 - j] / 8);
    bit = PNB[PNB_COUNT - j - 1] % 8;
    pt = (pnb >> j) % 2;
    key[word] = key[word] ^ (pt << bit);
  }

  // significant part insertion
  for (int j = 0; j < SIG_COUNT; ++j)
  {
    word = (SIG[SIG_COUNT - 1 - j] / 8);
    bit = SIG[SIG_COUNT - 1 - j] % 8;
    pt = (sig >> j) % 2;
    key[word] = key[word] ^ (pt << bit);
  }

  for (int l{ 0 }; l < 4; ++l)
  {
    key[l + 4] = key[l];
  }
}

//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~//
// pre processing part starts here
// iv's along with their key streams are collected
// this is done in the og encryption machinery
void collectKeyStream(int IDword, int IDbit, ul* masterKey)
{
  for (int i{ 0 };i < N;++i) {
    InitializeIV(zeroState);

    CopyState(DzeroState, zeroState, 16);
    CopyState(storedIV[i], zeroState, 16); // the ivs are stored to use in the attack
    InputDifference(DzeroState, IDword, IDbit);

    ENCRYPTION(zeroState, masterKey, false, 3);
    ENCRYPTION(DzeroState, masterKey, false, 3);

    CopyState(keyst[i], zeroState, 16);
    CopyState(Dkeyst[i], DzeroState, 16);
  }
}
// pre processing part starts here
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~//

// function to check threshold check for a guess
bool checkThresholdCross(ul sigGuess, int IDword, int IDbit, int ODword, int ODbit, ul* PNB, ul PNB_COUNT, ul* SIG, ul SIG_COUNT)
{
  ul count = 0.0;
  for (sampleLoop = 0; sampleLoop < N; ++sampleLoop)
  {
    // randomly select a pnb in each sample and run the state👇🏾
    pnbRandom = (pow(2, PNB_COUNT)) * drand48();
    generateKey(sigGuess, pnbRandom, guessKey, PNB, PNB_COUNT, SIG, SIG_COUNT);

    InsertKey(storedIV[sampleLoop], guessKey); // guess state with the pre chosen IV is formed
    CopyState(DstoredIV[sampleLoop], storedIV[sampleLoop], 16); // copied to create the diff. version of the guess state

    // the following the three steps are done for the exhaustive search
    CopyState(guesState, storedIV[sampleLoop], 16);
    CopyState(storedGuesState, storedIV[sampleLoop], 16);
    CopyState(bigZ, keyst[sampleLoop], 16);

    InputDifference(DstoredIV[sampleLoop], IDword, IDbit); //  the difference is injected into the diff. state
    // for the sake of not updating the keyst we copied the state into other state
    CopyState(z, keyst[sampleLoop], 16);
    CopyState(Dz, Dkeyst[sampleLoop], 16);
    // Z- X, Z1-X1
    SubtractStates(z, storedIV[sampleLoop]);
    SubtractStates(Dz, DstoredIV[sampleLoop]);

    // reverse rounds
    // 3 - 2 round
    BWRound(z, 3);
    BWRound(Dz, 3);

    XORDifference(z, Dz, DiffState, 16);
    bacwrdBit = DiffState[ODword] >> ODbit;

    if (bacwrdBit & 0x1)
      count++;
  }
  if (count >= T)
    return true;
  return false;
}


void calculateComplexity(ul* masterKey)
{
  auto start = chrono::high_resolution_clock::now();
  for (ul guess1 = 0; guess1 < totalSIG; ++guess1)
  {
    collectKeyStream(IDword_1, IDbit_1, masterKey);

    guesS = guess1;
    if (checkThresholdCross(guesS, IDword_1, IDbit_1, ODword_1, ODbit_1, PNB1, PNB1_COUNT, SIG1, SIG1_COUNT))
    {
      firstCompl = guess1 * N;
      for (ul guess2 = 0; guess2 < totalSIG; ++guess2)
      {

        collectKeyStream(IDword_2, IDbit_2, masterKey);

        guesS = (guess1 << 8) ^ guess2;
        if (checkThresholdCross(guesS, IDword_2, IDbit_2, ODword_2, ODbit_2, PNB2, PNB2_COUNT, SIG2, SIG2_COUNT))
        {
          secondCompl = guess2 * N;
          for (ul guess3 = 0; guess3 < totalSIG; ++guess3)
          {
            collectKeyStream(IDword_3, IDbit_3, masterKey);

            guesS = (guess1 << 16) ^ (guess2 << 8) ^ guess3;
            if (checkThresholdCross(guesS, IDword_3, IDbit_3, ODword_3, ODbit_3, PNB3, PNB3_COUNT, SIG3, SIG3_COUNT))
            {
              thirdCompl = guess3 * N;
              pnbGuess = 0, fourthCompl = 0;
              while (pnbGuess < totalPNB3)
              {
                generateKey(guesS, pnbGuess, guessKey, PNB3, PNB3_COUNT, SIG3, SIG3_COUNT);

                ENCRYPTION(guesState, guessKey, false, 3);
                fourthCompl++;
                if (AcidTest(guesState, bigZ))
                {
                  VfirstCompl.push_back(firstCompl);
                  VsecondCompl.push_back(secondCompl);
                  VthirdCompl.push_back(thirdCompl);
                  VfourthCompl.push_back(fourthCompl);

                  pnbGuess = totalPNB3;
                  guess3 = totalSIG;
                  guess2 = totalSIG;
                  guess1 = totalSIG;

                  auto end = chrono::high_resolution_clock::now();
                  VtotalTime.push_back(chrono::duration_cast<chrono::milliseconds>(end - start).count());
                }
                else
                {
                  CopyState(guesState, storedGuesState, 16);
                  pnbGuess++;
                }
              }
            }
          }
        }
      }
    }
  }
}



int main()
{
  srand48(time(NULL));
  auto mainStart = chrono::high_resolution_clock::now();
  ul masterKey[8];
  cout << "Complexity Calculation Started ... \n\n";
  for (int loop = 0;loop < sampleKeySize;++loop) {
    InitializeKey32(masterKey);
    calculateComplexity(masterKey);
  }
  double firstSum{ 0.0 };
  double secondSum{ 0.0 };
  double thirdSum{ 0.0 };
  double fourthSum{ 0.0 };
  double totalTimeSum{ 0.0 };

  for (auto& i : VfirstCompl)
    firstSum += i;
  for (auto& i : VsecondCompl)
    secondSum += i;
  for (auto& i : VthirdCompl)
    thirdSum += i;
  for (auto& i : VfourthCompl)
    fourthSum += i;
  for (auto& i : VtotalTime)
    totalTimeSum += i;

  cout << "Average firstcomp. = 2^{" << setprecision(4) << (double)log2(firstSum / sampleKeySize) << "}\n";
  cout << "Average secondcomp. = 2^{" << setprecision(4) << (double)log2(secondSum / sampleKeySize) << "}\n";
  cout << "Average thirdcomp. = 2^{" << setprecision(4) << (double)log2(thirdSum / sampleKeySize) << "}\n";
  cout << "Average fourthcomp. = 2^{" << setprecision(4) << (double)log2(fourthSum / sampleKeySize) << "}\n";
  cout << "Average totalcompl. = 2^{" << setprecision(4) << (double)log2((firstSum / sampleKeySize) + (secondSum / sampleKeySize) + (thirdSum / sampleKeySize) + (fourthSum / sampleKeySize)) << "}\n\n";

  cout << "Average Time = " << fixed << setprecision(3) << (double)(totalTimeSum / sampleKeySize) << " ms\n";
  auto mainEnd = chrono::high_resolution_clock::now();
  cout << "Time to Recover Key ~ " << chrono::duration<double, std::milli>(mainEnd - mainStart).count() << " ms ~ " << chrono::duration_cast<chrono::seconds>(mainEnd - mainStart).count() << " seconds\n";
}
