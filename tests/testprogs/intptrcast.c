int fn(short p1,
       short p2,
       short p3,
       short p4,
       short p5,
       short p6,
       short p7,
       short p8,
       short p9)
{
  return p1 + p2 + p3 + p4 + p5 + p6 + p7 + p8 + p9;
}

int main() {
  fn(0x123, 0x456, 0x789, 0xabc, 0xdef, 0xfed, 0xcba, 0xcba, 0xcba);
  return 0;
}
