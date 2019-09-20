#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>

int main() {
  volatile void* addr = mmap(
      (void*)0x10000000,
      2 << 20,
      PROT_READ | PROT_WRITE,
      MAP_PRIVATE | MAP_ANONYMOUS,
      -1,
      0);

  if ((long)addr < 0) {
    perror("mmap");
    return 1;
  }


  uint8_t i = 0;
  while (1) {
    *((volatile uint8_t*)addr) = i++;
  }
}
