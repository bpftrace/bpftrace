#include <assert.h>
#include <fcntl.h>
#include <stddef.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include <stdio.h>

typedef void (*funcptr_t)(void);

int main(int argc, char *argv[])
{
  if (argc < 2) {
    return 1;
  }

  int fd = open(argv[1], O_RDONLY);
  struct stat st;

  assert(fd >= 0);
  fstat(fd, &st);

  // Maps the file containing executable code and jumps to it.
  funcptr_t fn = (funcptr_t)mmap(
      NULL, st.st_size, PROT_EXEC, MAP_PRIVATE, fd, 0);
  assert(fn != MAP_FAILED);
  fn();

  return 0;
}
