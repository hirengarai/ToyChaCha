#include <iostream> // cin cout
#include <cmath>    // pow function
#include <cstdint>  // uint32_t
#include <cstdlib>  // drand48, srand48, strtoul, exit
#include <cstring>  // strcmp
#include <ctime>    // time
#include <vector>
#include <random>

using namespace std;

using ul = uint32_t;      // positive integer

#define BitsInWord 8
#define mod 256 // pow(2, BitsInWord)
// The outer parentheses are load bearing. Without them MOD(a + b) expands to
// a + (b % mod), because % binds tighter than +, and the word is never reduced
// to BitsInWord bits -- so the state stops matching Eq. 8 of the paper.
#define MOD(x) ((x) % mod) // making the number of BitsInWord bits


#define rotateleft(x, n) MOD((MOD(x) << (n)) ^ (MOD(x) >> (BitsInWord - n)))
#define rotateright(x, n) MOD((MOD(x) >> (n)) ^ (MOD(x) << (BitsInWord - n)))
#define update(a, b, n) MOD((rotateleft(MOD(a) ^ MOD(b), (n))))
#define drandom ((ul)mod * drand48()) // random number between 0 to 255


// Forward QR ---------------------------
#define FWQR4(a,b,c,d) \
a = MOD(a + b); \
d = update(a,d,4);

#define XFWQR4(a,b,c,d) \
a = a ^ b; \
d = update(a,d,4);



#define FWQR3(a,b,c,d) \
c = MOD(c + d); \
b = update(b,c,3);

#define XFWQR3(a,b,c,d) \
c = c ^ d; \
b = update(b,c,3);



#define FWQR2(a,b,c,d) \
a = MOD(a + b); \
d = update(a,d,2);

#define XFWQR2(a,b,c,d) \
a = a ^ b; \
d = update(a,d,2);



#define FWQR1(a,b,c,d) \
c = MOD(c + d); \
b = update(b,c,1);

#define XFWQR1(a,b,c,d) \
c = c ^ d; \
b = update(b,c,1);

// #1st half
#define FWQR_4_3(a,b,c,d) \
FWQR4(a,b,c,d);\
FWQR3(a,b,c,d);

#define XFWQR_4_3(a,b,c,d) \
XFWQR4(a,b,c,d);\
XFWQR3(a,b,c,d);

// #2nd half
#define FWQR_2_1(a,b,c,d)\
FWQR2(a,b,c,d); \
FWQR1(a,b,c,d);

#define XFWQR_2_1(a,b,c,d)\
XFWQR2(a,b,c,d); \
XFWQR1(a,b,c,d);

// full QR
#define FWfullQR(a,b,c,d) \
FWQR_4_3(a,b,c,d); \
FWQR_2_1(a,b,c,d);

#define XFWfullQR(a,b,c,d) \
XFWQR_4_3(a,b,c,d); \
XFWQR_2_1(a,b,c,d);




//  Backward QR ---------------------------
#define BWQR1(a,b,c,d) \
b = rotateright(b,1)^c;\
c = MOD(c - d);

#define BWQR2(a,b,c,d) \
d = rotateright(d,2)^a; \
a = MOD(a - b);

#define BWQR3(a,b,c,d) \
b = rotateright(b,3)^c; \
c = MOD(c - d);

#define BWQR4(a,b,c,d) \
d = rotateright(d,4)^a; \
a = MOD(a - b);

// #1st half
#define BWQR_1_2(a,b,c,d)\
BWQR1(a,b,c,d);\
BWQR2(a,b,c,d);

// #2nd half
#define BWQR_3_4(a,b,c,d)\
BWQR3(a,b,c,d);\
BWQR4(a,b,c,d)

// full QR
#define BWfullQR(a,b,c,d) \
BWQR_1_2(a,b,c,d);\
BWQR_3_4(a,b,c,d);
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~//


// The single engine behind mtrandom() and unitrandom(). SeedRun() seeds it and
// drand48() together, so one --seed value reproduces a whole run exactly.
std::mt19937& RandomEngine()
{
  thread_local std::mt19937 engine(std::random_device{}());
  return engine;
}


void SeedRun(unsigned long seed)
{
  RandomEngine().seed((std::mt19937::result_type)seed);
  srand48((long)seed);
}


ul mtrandom(const int min, const int max)
{
  std::uniform_int_distribution<int> dist(min, max);
  return dist(RandomEngine());
}


double unitrandom() {
  std::uniform_real_distribution<double> dist(0.0, 1.0);
  return dist(RandomEngine());
}


void ShowOnScreen(ul* x, int size)
{
  int i;
  for (i = 0; i < size; ++i)
  {
    printf("%02x ", x[i]);
    if (i > 0 && i % 4 == 3)
      printf("\n");
  }
  printf("\n");
}


// to check the equality of two states
// returns true if two state matrices are equal
bool AcidTest(ul* x, ul* y) {
  bool flag = true;
  for (ul i{ 0 };i < 16;++i) {
    if (x[i] != y[i])
    {
      flag = false;
      break;
    }
  }
  return flag;
}


// IV initialisation
void InitializeIV(ul* x)
{
  int i;
  for (i = 12; i < 16; ++i)
  {
    x[i] = mtrandom(0, mod - 1); // IV
    // x[i] = drandom; // IV
  }
  x[0] = 0x65;
  x[1] = 0x6e;
  x[2] = 0x32;
  x[3] = 0x74;
}


// key initialisations
// 64 bit key
void InitializeKey64(ul* k)
{
  for (int i = 0; i < 8; ++i)
  {
    k[i] = mtrandom(0, mod - 1);
    // k[i] = drandom;
  }
}


// 32 bit key
void InitializeKey32(ul* k)
{
  for (int i = 0; i < 4; ++i)
  {
    k[i] = mtrandom(0, mod - 1);
    // k[i] = drandom;
    k[i + 4] = k[i];
  }
}


// fitting the key k into the state matrix x
void InsertKey(ul* x, ul* k)
{
  for (int j = 4; j < 12; ++j)
  {
    x[j] = k[j - 4];
  }
}


// copying state
// values of x are copied in x1 from start word to end word
void CopyState(ul* x1, ul* x, int n)
{
  for (int i{ 0 }; i < n; ++i)
    x1[i] = x[i];
}


// fucntion to input difference
void InputDifference(ul* x, int word, int bit)
{
  int pattern = 0x1 << bit;
  x[word] = x[word] ^ pattern;
}


// function to store the xor difference z between two terms x and y
void XORDifference(ul* x, ul* x1, ul* y, int n)
{
  for (int j = 0; j < n; ++j)
  {
    y[j] = x[j] ^ x1[j];
  }
}


//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~//
// sum is stored in x
void AddStates(ul* x, ul* x1)
{
  for (int j = 0; j < 16; ++j)
  {
    x[j] = MOD(x[j] + x1[j]);
  }
}


// subtraction of x1 from x and is stored in x
void SubtractStates(ul* x, ul* x1)
{
  for (int j = 0; j < 16; ++j)
  {
    x[j] = MOD(x[j] - x1[j]);
  }
}


// function to store the xor difference count number between two terms x and x1
// check digit defines the column no. where the id is given and varies from 0,1,2,3
// bool c = false means whole 16 words are to be checked.
int NumberOfDifferences(ul* x, ul* x1, int check_digit, bool c)
{
  if (c) {
    int temp = 0;
    for (int j = check_digit; j < 16; j += 4)
    {
      for (int k = 0; k < 8; ++k)
      {
        int pattern = 0x1 << k;
        if (((x[j] ^ x1[j]) & pattern) != 0)
          temp++;
      }
    }
    return temp;
  }
  else {
    int temp = 0;
    for (int j = 0; j < 16; ++j)
    {
      for (int k = 0; k < 8; ++k)
      {
        int pattern = 0x1 << k;
        if (((x[j] ^ x1[j]) & pattern) != 0)
          temp++;
      }
    }
    return temp;
  }
}


void FWRound(ul* x, int round) { // round numbering means even or odd round
  if (round & 1)
  {
    FWfullQR((x[0]), (x[4]), (x[8]), (x[12]));
    FWfullQR((x[1]), (x[5]), (x[9]), (x[13]));
    FWfullQR((x[2]), (x[6]), (x[10]), (x[14]));
    FWfullQR((x[3]), (x[7]), (x[11]), (x[15]));
  }
  else
  {
    FWfullQR((x[0]), (x[5]), (x[10]), (x[15]));
    FWfullQR((x[1]), (x[6]), (x[11]), (x[12]));
    FWfullQR((x[2]), (x[7]), (x[8]), (x[13]));
    FWfullQR((x[3]), (x[4]), (x[9]), (x[14]));
  }
}

// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~//
// half rounds
void FW1HalfEvenRF(ul* x)
{
  FWQR_4_3((x[0]), (x[5]), (x[10]), (x[15]));
  FWQR_4_3((x[1]), (x[6]), (x[11]), (x[12]));
  FWQR_4_3((x[2]), (x[7]), (x[8]), (x[13]));
  FWQR_4_3((x[3]), (x[4]), (x[9]), (x[14]));
}
void FW1HalfOddRF(ul* x)
{
  FWQR_4_3((x[0]), (x[4]), (x[8]), (x[12]));
  FWQR_4_3((x[1]), (x[5]), (x[9]), (x[13]));
  FWQR_4_3((x[2]), (x[6]), (x[10]), (x[14]));
  FWQR_4_3((x[3]), (x[7]), (x[11]), (x[15]));
}
void FW2HalfEvenRF(ul* x)
{
  FWQR_2_1((x[0]), (x[5]), (x[10]), (x[15]));
  FWQR_2_1((x[1]), (x[6]), (x[11]), (x[12]));
  FWQR_2_1((x[2]), (x[7]), (x[8]), (x[13]));
  FWQR_2_1((x[3]), (x[4]), (x[9]), (x[14]));
}
void FW2HalfOddRF(ul* x)
{
  FWQR_2_1((x[0]), (x[4]), (x[8]), (x[12]));
  FWQR_2_1((x[1]), (x[5]), (x[9]), (x[13]));
  FWQR_2_1((x[2]), (x[6]), (x[10]), (x[14]));
  FWQR_2_1((x[3]), (x[7]), (x[11]), (x[15]));
}


// backward rounds
void BWRound(ul* x, int round) {// round numbering means even or odd round
  if (round & 1)
  {
    BWfullQR((x[0]), (x[4]), (x[8]), (x[12]));
    BWfullQR((x[1]), (x[5]), (x[9]), (x[13]));
    BWfullQR((x[2]), (x[6]), (x[10]), (x[14]));
    BWfullQR((x[3]), (x[7]), (x[11]), (x[15]));
  }
  else
  {
    BWfullQR((x[0]), (x[5]), (x[10]), (x[15]));
    BWfullQR((x[1]), (x[6]), (x[11]), (x[12]));
    BWfullQR((x[2]), (x[7]), (x[8]), (x[13]));
    BWfullQR((x[3]), (x[4]), (x[9]), (x[14]));
  }
}

void BW1HalfEvenRF(ul* x)
{
  BWQR_1_2((x[0]), (x[5]), (x[10]), (x[15]));
  BWQR_1_2((x[1]), (x[6]), (x[11]), (x[12]));
  BWQR_1_2((x[2]), (x[7]), (x[8]), (x[13]));
  BWQR_1_2((x[3]), (x[4]), (x[9]), (x[14]));
}
void BW1HalfOddRF(ul* x)
{
  BWQR_1_2((x[0]), (x[4]), (x[8]), (x[12]));
  BWQR_1_2((x[1]), (x[5]), (x[9]), (x[13]));
  BWQR_1_2((x[2]), (x[6]), (x[10]), (x[14]));
  BWQR_1_2((x[3]), (x[7]), (x[11]), (x[15]));
}

void BW2HalfEvenRF(ul* x)
{
  BWQR_3_4((x[0]), (x[5]), (x[10]), (x[15]));
  BWQR_3_4((x[1]), (x[6]), (x[11]), (x[12]));
  BWQR_3_4((x[2]), (x[7]), (x[8]), (x[13]));
  BWQR_3_4((x[3]), (x[4]), (x[9]), (x[14]));
}

void BW2HalfOddRF(ul* x)
{
  BWQR_3_4((x[0]), (x[4]), (x[8]), (x[12]));
  BWQR_3_4((x[1]), (x[5]), (x[9]), (x[13]));
  BWQR_3_4((x[2]), (x[6]), (x[10]), (x[14]));
  BWQR_3_4((x[3]), (x[7]), (x[11]), (x[15]));
}


// rounds round encryption
void ENCRYPTION(ul* x, ul* k, bool flag, int rounds) // flag = true means half round in encryption
{
  ul x0[16]{ 0 };
  InsertKey(x, k);
  CopyState(x0, x, 16);
  if (flag) {
    for (int i{ 1 };i <= rounds;++i) {
      FWRound(x, i);
    }
    if (rounds & 1)
    {
      FW1HalfEvenRF(x);
    }
    else {
      FW1HalfOddRF(x);
    }
  }
  else {
    for (int i{ 1 };i <= rounds;++i) {
      FWRound(x, i);
    }
  }
  AddStates(x, x0);
}


// all the values of x are unset
void ReSetState(ul* x, ul size)
{
  for (ul i{ 0 }; i < size; ++i)
  {
    x[i] = 0;
  }
}

void SortByBias(vector<double>& PNB_BIAS, vector<ul>& PNB)
{
  int flag;
  for (int l = (int)PNB.size() - 1; l >= 0; --l)
  {
    flag = 0;
    for (int j = 0; j < l; ++j)
    {
      if (PNB_BIAS[j] < PNB_BIAS[j + 1])
      {
        swap(PNB_BIAS.at(j), PNB_BIAS.at(j + 1));
        swap(PNB.at(j), PNB.at(j + 1));
        flag = 1;
      }
    }
    if (flag == 0)
    {
      break;
    }
  }
  cout << "\n \n The PNBs in descending order of BIAS is as follows 👇🏾" << endl;
  ul t = 0;
  cout << "{";
  for (const ul& n : PNB)
  {
    t++;
    if (t == PNB.size()) {
      cout << n;
    }
    else
    {
      cout << n << ", ";
    }
  }
  cout << "}\n";
}


// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~//
// Command line options, so a published run can be repeated without editing and
// recompiling the source.
//   --seed S   fix the seed of every random draw   (default: the clock)
//   --keys K   how many random keys to average over (complexity programs only)
struct Options
{
  unsigned long seed;
  long keys;
};


Options ParseOptions(int argc, char** argv, long defaultKeys)
{
  Options opt{ (unsigned long)time(NULL), defaultKeys };
  for (int i = 1; i < argc; ++i)
  {
    if (strcmp(argv[i], "--seed") == 0 && i + 1 < argc)
      opt.seed = strtoul(argv[++i], NULL, 10);
    else if (strcmp(argv[i], "--keys") == 0 && i + 1 < argc)
      opt.keys = strtol(argv[++i], NULL, 10);
    else
    {
      cerr << "usage: " << argv[0] << " [--seed S] [--keys K]\n";
      exit(EXIT_FAILURE);
    }
  }
  SeedRun(opt.seed);
  return opt;
}
