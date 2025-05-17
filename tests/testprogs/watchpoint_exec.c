#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

static uint8_t insns[] = {
  0x90, // nop
  0xc3  // retq
};

int main()
{
  size_t len = getpagesize();
  void *addr = mmap((void *)0x10000000,
                    len,
                    PROT_READ | PROT_WRITE | PROT_EXEC,
                    MAP_PRIVATE | MAP_ANONYMOUS,
                    -1,
                    0);
  if (addr == MAP_FAILED) {
    perror("mmap");
    exit(EXIT_FAILURE);
  }

  memcpy(addr, insns, sizeof(insns));
  void (*func)(void);
  func = addr;
  (*func)();

  if (munmap(addr, len) == -1) {
    perror("munmap");
  }
  return 0;
}
