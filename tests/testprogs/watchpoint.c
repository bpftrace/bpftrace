#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

int main()
{
  volatile void* addr = mmap((void*)0x10000000,
                             2 << 20,
                             PROT_READ | PROT_WRITE,
                             MAP_PRIVATE | MAP_ANONYMOUS,
                             -1,
                             0);

  if ((long)addr < 0) {
    perror("mmap");
    return 1;
  }

  mode_t old_umask = umask(S_IWGRP | S_IROTH | S_IWOTH);
  FILE* addr_fp = fopen("/tmp/watchpoint_mem", "w");

  if (!addr_fp)
    perror("failed to open file in /tmp");

  fprintf(addr_fp, "%p", addr);
  fclose(addr_fp);

  uint8_t i = 0;
  while (i < 10) {
    *((volatile uint8_t*)addr) = i++;
    // 250ms*10 sleep, enough for watchpoint trigger
    usleep(250 * 1000);
  }

  umask(old_umask);
}
