// the aumasson attack program in the 8 bit Toy-ChaCha-32 cipher to the counter of multiple id-od attack approach
// (ID - OD) = ((13,0) - (1,6))
// 3 round attack
// 2 round distinguisher

// command to execute the prog 👇
// g++ singleidodattack.cpp && ./a.out

#include <ctime>     // to use time
#include <iomanip>   // decimal numbers upto certain places
#include <chrono>
#include "chacha.h"


int IDword = 13, IDbit = 0; // input difference
int ODword = 1, ODbit = 6; // output difference
const ul N = 94, T = 84; // N = number of samples, T = threshold

ul SIG[] = { 15, 14, 13, 12, 11, 10, 9, 8 }; // significant bits
ul PNB[] = { 7,6,5,4,3,2,1,0, 23, 22, 21, 20, 19, 18, 17, 16,  31, 30, 29, 28, 27, 26, 25, 24 }; // pnbs

int SIG_COUNT = sizeof(SIG) / sizeof(SIG[0]);
int PNB_COUNT = sizeof(PNB) / sizeof(PNB[0]);
int totalSig = pow(2, SIG_COUNT); // all possible numbers with significant bits count
int totalPNB = pow(2, PNB_COUNT); // all possible numbers with non-significant bits count

ul guessKey[8], zeroState[16], DzeroState[16], guesState[16], z[16], Dz[16], DiffState[16], bigZ[16], storedGuesState[16], storedIV[N][16], DstoredIV[N][16], keyst[N][16], Dkeyst[N][16], bacwrdBit, sigGuess, pnbRandom, pnbGuess, WORD, BIT, sampleLoop;

// generateKey from significant and pnb part of the key
void generateKey(ul sig, ul pnb, ul* key)
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
void collectKeyStream(ul* masterKey)
{
  cout << "\nKeystream collection started ...\n\n";
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
  cout << "\nKeystream collection ended ...\n\n";
}
// pre processing part starts here
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~//

// function to check threshold check for a guess
bool checkThresholdCross(ul Guess)
{
  ul count = 0.0;
  for (sampleLoop = 0; sampleLoop < N; ++sampleLoop)
  {
    // randomly select a pnb in each sample and run the state👇🏾
    pnbRandom = (pow(2, PNB_COUNT)) * drand48();
    generateKey(Guess, pnbRandom, guessKey);

    InsertKey(storedIV[sampleLoop], guessKey); // guess state with the pre chosen IV is formed
    CopyState(DstoredIV[sampleLoop], storedIV[sampleLoop], 16); // copied to create the diff. version of the guess state
    InputDifference(DstoredIV[sampleLoop], IDword, IDbit); //  the difference is injected into the diff. state

    // the following the three steps are done for the exhaustive search
    CopyState(guesState, storedIV[sampleLoop], 16);
    CopyState(storedGuesState, storedIV[sampleLoop], 16);
    CopyState(bigZ, keyst[sampleLoop], 16);


    // for the sake of not updating the keyst we copied the state into other state
    CopyState(z, keyst[sampleLoop], 16);
    CopyState(Dz, Dkeyst[sampleLoop], 16);
    // Z- X, Z1-X1
    SubtractStates(z, storedIV[sampleLoop]);
    SubtractStates(Dz, DstoredIV[sampleLoop]);

    // reverse rounds ---------------------------------------------
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


void recoverKey(ul* masterKey)
{
  cout << "Key Recovery Started ...\n \n";
  ul count, guess, match;

  collectKeyStream(masterKey);

  // attack starts here
  for (guess = 0; guess < totalSig; ++guess)
  {
    // guess the significant and pnb part
    if (checkThresholdCross(guess))
    {
      pnbGuess = 0;
      while (pnbGuess < totalPNB)
      {
        generateKey(guess, pnbGuess, guessKey);

        ENCRYPTION(guesState, guessKey, false, 3);

        if (AcidTest(guesState, bigZ))
        {
          printf("✅ Hurray !!! The master key recovery is successful and the master key is \n");
          ShowOnScreen(guessKey, 8);
          pnbGuess = totalPNB;
          guess = totalSig;
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

int main()
{
  srand48(time(NULL));
  auto start = chrono::high_resolution_clock::now();
  ul masterKey[8];
  InitializeKey32(masterKey);
  cout << "The OG Master key is \n";
  ShowOnScreen(masterKey, 8);
  recoverKey(masterKey);
  auto end = chrono::high_resolution_clock::now();
  cout << "Time to Recover Key ~ " << chrono::duration<double, std::milli>(end - start).count() << " millisec ~ " << chrono::duration_cast<chrono::seconds>(end - start).count() << " seconds\n";
}