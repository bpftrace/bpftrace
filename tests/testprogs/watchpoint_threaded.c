#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

void *work(void *)
{
  printf("Working...\n");
  volatile void *addr = mmap((void *)0x10000000,
                             2 << 20,
                             PROT_READ | PROT_WRITE,
                             MAP_PRIVATE | MAP_ANONYMOUS,
                             -1,
                             0);

  if ((long)addr < 0) {
    perror("mmap");
    return NULL;
  }

  uint8_t i = 0;
  while (i < 10) {
    *((volatile uint8_t *)addr) = i++;
    // 250ms*10 sleep, enough for watchpoint trigger
    usleep(250 * 1000);
  }

  return NULL;
}

int main()
{
  pthread_t tid;
  if (pthread_create(&tid, NULL, work, 0)) {
    perror("pthread_create");
  }

  if (pthread_join(tid, NULL)) {
    perror("pthread_join");
  }

  printf("Exiting...\n");
}
