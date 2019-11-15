// a is on the stack
int fn(short rdi, short rsi, short rdx, short rcx, short r8, short r9, short a) {
    return rdi + rsi + rdx + rcx + r8 + r9 + a;
}

int main() {
  fn(0x123, 0x456, 0x789, 0xabc, 0xdef, 0xfed, 0xcba);
  return 0;
}
