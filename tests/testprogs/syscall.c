#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

void usage()
{
  printf("Usage:\n");
  printf("\t./syscall <syscall name> [<arguments>]\n");
  printf("Supported Syscalls:\n");
  printf("\t nanosleep [$N] (default args: 100ns)\n");
#if defined(SYS_open)
  printf("\t open\n");
#endif
  printf("\t openat\n");
  printf("\t read\n");
  printf("\t execve <path> [<arguments>] (at most 128 arguments)\n");
}

int gen_nanosleep(int argc, char *argv[])
{
  struct timespec req;
  const char *arg = argv[2];
  req.tv_sec = 0;
  req.tv_nsec = 100;
  if (argc > 2)
  {
    if (!isdigit(*arg) || !isdigit(arg[strlen(arg) - 1]))
    {
      printf("Invalid argument: %s; the argument should be a non-negative "
             "number with no sign\n",
             arg);
      return 1;
    }
    double time;
    char tail = '\0';
    sscanf(arg, "%le%c", &time, &tail);
    if (tail != '\0')
    {
      printf("Argument '%s' should only contain numerial charactors\n", arg);
      return 1;
    }
    // if time is less than 1 nsec, round up to 1 nsec, as with sleep command
    if (time > 0 && time < 1)
    {
      time = 1;
    }
    req.tv_sec = (int)(time / 1e9);
    req.tv_nsec = (int)(time - req.tv_sec * 1e9);
  }
  int r = syscall(SYS_nanosleep, &req, NULL);
  if (r)
  {
    perror("Error in syscall nanosleep");
    return 1;
  }
  return 0;
}

// the returned string was created with malloc()
// @ path_suffix should start with '/'
char *get_tmp_file_path(const char *path_suffix)
{
  const char *tmpdir = getenv("TMPDIR");
  if (tmpdir == NULL)
  {
    tmpdir = "/tmp";
  }
  int path_len = strlen(tmpdir) + strlen(path_suffix);
  char *path = (char *)malloc((path_len + 1) * sizeof(char));
  memset(path, '\0', path_len + 1);
  strncat(path, tmpdir, strlen(tmpdir));
  strncat(path, path_suffix, strlen(path_suffix));
  return path;
}

int gen_open_openat(bool is_sys_open)
{
  char *file_path = get_tmp_file_path(
      "/bpftrace_runtime_test_syscall_gen_open_temp");
  int fd = -1;

  if (is_sys_open)
  {
#if defined(SYS_open)
    fd = syscall(SYS_open, file_path, O_CREAT);
#endif
  }
  else
  {
    fd = syscall(SYS_openat, AT_FDCWD, file_path, O_CREAT);
  }

  if (fd < 0)
  {
    perror("Error in syscall open/openat");
    free(file_path);
    return 1;
  }
  close(fd);
  remove(file_path);
  free(file_path);
  return 0;
}

int gen_read()
{
  char *file_path = get_tmp_file_path(
      "/bpftrace_runtime_test_syscall_gen_read_temp");
  int fd = open(file_path, O_CREAT);
  if (fd < 0)
  {
    perror("Error in syscall read when creating temp file");
    free(file_path);
    return 1;
  }
  char buf[10];
  int r = syscall(SYS_read, fd, (void *)buf, 0);
  close(fd);
  remove(file_path);
  free(file_path);
  if (r < 0)
  {
    perror("Error in syscall read");
    return 1;
  }
  return 0;
}

int gen_execve(int argc, char *argv[])
{
  if (argc < 3)
  {
    printf("Indicate which process to execute.\n");
    return 1;
  }
  char *newargv[129] = { NULL };
  char *newenv[] = { NULL };
  newargv[0] = argv[2];
  int arg_nm = argc - 3;
  if (arg_nm > 128)
  {
    printf("Too many arguments: at most 128 arguments, %d given\n", arg_nm);
    return 1;
  }
  for (int i = 0; i < argc; ++i)
  {
    newargv[1 + i] = argv[3 + i];
  }
  syscall(SYS_execve, argv[2], newargv, newenv);
  // execve returns on error
  perror("Error in syscall execve");
  return 1;
}

int main(int argc, char *argv[])
{
  if (argc < 2)
  {
    usage();
    return 1;
  }
  const char *syscall_name = argv[1];
  int r = 0;

  if (strcmp("--help", syscall_name) == 0 || strcmp("-h", syscall_name) == 0)
  {
    usage();
  }
  else if (strcmp("nanosleep", syscall_name) == 0)
  {
    r = gen_nanosleep(argc, argv);
  }
  else if (strcmp("openat", syscall_name) == 0)
  {
    r = gen_open_openat(false);
  }
#if defined(SYS_open)
  else if (strcmp("open", syscall_name) == 0)
  {
    r = gen_open_openat(true);
  }
#endif
  else if (strcmp("read", syscall_name) == 0)
  {
    r = gen_read();
  }
  else if (strcmp("execve", syscall_name) == 0)
  {
    r = gen_execve(argc, argv);
  }
  else
  {
    printf("%s is not supported yet\n", syscall_name);
    usage();
    r = 1;
  }

  return r;
}
