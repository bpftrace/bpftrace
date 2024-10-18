#include <linux/bpf.h>
#include <linux/unistd.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char *argv[])
{
  if (argc != 3) {
    return 1;
  }
  usleep(1000000);

  union bpf_attr attr;
  int cmd = atoi(argv[1]);
  unsigned int size = atoi(argv[2]);
  syscall(__NR_bpf, cmd, &attr, size);

  return 0;
}
