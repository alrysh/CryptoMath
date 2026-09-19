#include <iostream>
#include <my_crypto_lib.hpp>

int main() {
  DlogResult res;
  res = baby_giant_step_interactive();
  return 0;
}