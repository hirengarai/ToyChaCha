#include<iostream>
#include<cmath>
#include<iomanip>

using namespace std;

double cumulativeNormal(double x) {
  return 0.5 * std::erfc(-x * M_SQRT1_2);
}

int main() {
  int keySize = 32;
  int PNB_COUNT = 24;
  int SIG_COUNT = keySize - PNB_COUNT;
  int totalSIG = pow(2, SIG_COUNT);

  double epsilon_d = .91;
  double epsilon_a = 1;
  double epsilon = epsilon_a * epsilon_d;
  double temp = 1 - epsilon * epsilon;
  int alpha = 40;

  double n = ((sqrt(alpha * log(4)) + 3.4 * sqrt(temp)) / (epsilon_a * epsilon_d));
  double N = n * n;

  double T = N / 2 * (1 + epsilon_a * epsilon_d) - 1.5 * sqrt(N * temp);
  double COMPL = totalSIG * N + pow(2, keySize - alpha) + pow(2, PNB_COUNT);

  cout << fixed << "Data Compl. = " << setprecision(2) << N << " ~ " << log2(N) << "\n";
  cout << fixed << "Threshold = " << setprecision(2) << T << " ~ " << log2(T) << "\n";
  cout << fixed << "Total Complexity = " << setprecision(2) << log2(COMPL) << "\n";
  cout << "---" << endl;

}
