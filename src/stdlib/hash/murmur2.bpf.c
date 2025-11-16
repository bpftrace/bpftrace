unsigned long __murmur_hash_2(void *stack, unsigned char num_frames, unsigned long seed) {
  const unsigned long m = 0xc6a4a7935bd1e995LLU;
  const int r = 47;
  unsigned long id = seed ^ (num_frames * m);
  unsigned char i = 0;

  while (i < num_frames) {
    unsigned long k = ((unsigned long *)stack)[i];
    k *= m;
    k ^= k >> r;
    k *= m;
    id ^= k;
    id *= m;
    ++i;
  }

  return id;
}
