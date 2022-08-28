// the chosenIV attack program in the 8 bit Toy-ChaCha-32 cipher
// (ID - OD) = ((13,0) - (1,6))
// 3.5 round attack
// 2 round distinguisher

// command to execute the prog 👇
// g++ chosenivattack.cpp && ./a.out

#include <ctime>     // to use time
#include <iomanip>   // decimal numbers upto certain places
#include <chrono>
#include "chacha.h"


int IDword = 13, IDbit = 0; // Inpur difference
int ODword = 1, ODbit = 6; // output difference

const ul N = 185, T = 119; // N = number of samples, T = threshold

int ID_SIG[] = { 15, 14, 13, 12, 11, 10, 9, 8 };
int SIG[] = { 23, 22, 21, 20, 17, 16, 29, 28, 27 };
int PNB[] = { 7, 6, 5, 4, 3, 2, 1, 0, 19, 18, 31, 30, 26, 25, 24 };


int ID_SIG_COUNT = sizeof(ID_SIG) / sizeof(ID_SIG[0]);
int SIG_COUNT = sizeof(SIG) / sizeof(SIG[0]);
int PNB_COUNT = sizeof(PNB) / sizeof(PNB[0]);


int totalIDsig = pow(2, ID_SIG_COUNT);
int totalSig = pow(2, SIG_COUNT);
int totalPNB = pow(2, PNB_COUNT);

ul guessKey[8], zeroState[16], DzeroState[16], guesState[16], z[16], Dz[16], DiffState[16], bacwrdBit, sigPart, pnbRandom, pnbGuess, WORD, BIT, sampleLoop, compare[16], bigZ[16], storedGuesState[16], storedIV[N][16], DstoredIV[N][16], keyst[N][16], Dkeyst[N][16];
int IV[256];

// key_generation from significant and pnb
void generateKey(ul idsig, ul sig, ul pnb, ul* key)
{
  ul word, bit, pt;
  ReSetState(key, 8);

  //id significant part insertion
  for (int j = 0; j < ID_SIG_COUNT; ++j)
  {
    word = (ID_SIG[ID_SIG_COUNT - j - 1] / 8);
    bit = ID_SIG[ID_SIG_COUNT - j - 1] % 8;
    pt = (idsig >> j) % 2;
    key[word] = key[word] ^ (pt << bit);
  }

  // significant part insertion
  for (int j = 0; j < SIG_COUNT; ++j)
  {
    word = (SIG[SIG_COUNT - j - 1] / 8);
    bit = SIG[SIG_COUNT - j - 1] % 8;
    pt = (sig >> j) % 2;
    key[word] = key[word] ^ (pt << bit);
  }

  // pnb part insertion
  for (int j = 0; j < PNB_COUNT; ++j)
  {
    word = (PNB[PNB_COUNT - 1 - j] / 8);
    bit = PNB[PNB_COUNT - j - 1] % 8;
    pt = (pnb >> j) % 2;
    key[word] = key[word] ^ (pt << bit);
  }

  for (int l{ 0 }; l < 4; ++l)
  {
    key[l + 4] = key[l];
  }
}

void findIV(int* IV, int IVsize) {
  ul x[16], Dx[16], k[8], keyCounter{ 0 }, IVcounter;

  for (int i{ 0 }; i < IVsize;++i) {
    IV[i] = -1;
  }
  while (keyCounter <= totalIDsig - 1) {
    IVcounter = 0;
    while (IVcounter <= totalIDsig - 1) {
      InitializeIV(x);
      InitializeKey32(k);
      k[IDword % 4] = k[(IDword % 4) + 4] = keyCounter;
      InsertKey(x, k);
      x[IDword] = IVcounter;
      CopyState(Dx, x, 16);
      InputDifference(Dx, IDword, IDbit);
      // 0 - 1 round
      FWRound(x, 1);
      FWRound(Dx, 1);
      if (NumberOfDifferences(x, Dx, IDword % 4, true) == 10) {
        IV[keyCounter] = IVcounter;
        IVcounter = totalIDsig;
      }
      else {
        IVcounter++;
      }
    }
    keyCounter++;
  }
}

void collectKeyStream(ul* masterKey, ul IDguess, int* IV)
{

  for (int i{ 0 };i < N;++i) {
    InitializeIV(zeroState);
    zeroState[IDword] = IV[IDguess];
    CopyState(DzeroState, zeroState, 16);
    CopyState(storedIV[i], zeroState, 16); // the ivs are stored to use in the attack
    InputDifference(DzeroState, IDword, IDbit);

    ENCRYPTION(zeroState, masterKey, true, 3);
    ENCRYPTION(DzeroState, masterKey, true, 3);

    CopyState(keyst[i], zeroState, 16);
    CopyState(Dkeyst[i], DzeroState, 16);
  }
}



bool checkThresholdCross(ul IDguess, ul Siguess)
{
  ul count = 0.0;
  for (sampleLoop = 0; sampleLoop < N; ++sampleLoop)
  {
    // randomise pnb each times 👇🏾
    pnbRandom = totalPNB * drand48();
    generateKey(IDguess, Siguess, pnbRandom, guessKey);
    //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~//

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
    // 3.5 - 3 round
    BW2HalfEvenRF(z);
    BW2HalfEvenRF(Dz);
    // 3 - 2 round
    BWRound(z, 1);
    BWRound(Dz, 1);

    XORDifference(z, Dz, DiffState, 16);
    bacwrdBit = DiffState[1] >> 6;

    if (bacwrdBit & 1)
      count++;
  }
  if (count >= T)
    return true;
  return false;
}

void recoverKey(ul* masterKey, int* IV)
{
  cout << "\nKey Recovery Started ...\n\n";
  ul count, IDguess, Siguess, match;

  for (IDguess = 0;IDguess < totalIDsig;++IDguess) {
    if (IV[IDguess] == -1)
      continue;

    collectKeyStream(masterKey, IDguess, IV);

    for (Siguess = 0; Siguess < totalSig; ++Siguess)
    {
      if (checkThresholdCross(IDguess, Siguess))
      {
        pnbGuess = 0;
        while (pnbGuess < totalPNB)
        {
          generateKey(IDguess, Siguess, pnbGuess, guessKey);

          ENCRYPTION(guesState, guessKey, true, 3);

          if (AcidTest(guesState, bigZ))
          {
            printf("✅ Hurray !!! The master key recovery is successful and the master key is \n");
            ShowOnScreen(guessKey, 8);
            pnbGuess = totalPNB;
            Siguess = totalSig;
            IDguess = totalIDsig;
          }
          else
          {
            CopyState(guesState, storedGuesState, 16);
            pnbGuess++;
          }
        }
      }
      else
      {
        exit;
      }
    }
  }

}



int main()
{
  auto start = chrono::high_resolution_clock::now();
  srand(time(NULL));
  // ul masterKey[8] = { 0x4f, 0x60, 0xa3, 0xe7,0x4f, 0x60, 0xa3, 0xe7 };
  ul masterKey[8];
  InitializeKey32(masterKey);
  cout << "The OG Master key is \n";
  ShowOnScreen(masterKey, 8);

  findIV(IV, totalIDsig);
  recoverKey(masterKey, IV);

  auto end = chrono::high_resolution_clock::now();
  cout << "time taken is " << chrono::duration_cast<chrono::seconds>(end - start).count() << " seconds\n";
}
