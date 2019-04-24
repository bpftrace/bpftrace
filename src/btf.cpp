#include <iostream>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/utsname.h>
#include <string.h>
#include "btf.h"
#include "types.h"
#include "bpftrace.h"

#ifdef HAVE_LIBBPF
#include <linux/bpf.h>
#include <linux/btf.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>

#define MAX_ERRNO 4095
#define IS_ERR_VALUE(x) ((x) >= (unsigned long)-MAX_ERRNO)

namespace bpftrace {

static inline long PTR_ERR(const void *ptr)
{
  return (long) ptr;
}

static inline bool IS_ERR(const void *ptr)
{
  return IS_ERR_VALUE((unsigned long) ptr);
}

static int libbpf_print(enum libbpf_print_level level, const char *msg, va_list ap)
{
  fprintf(stderr, "BTF: (%d) ", level);
  return vfprintf(stderr, msg, ap);
}

void BTF::init(unsigned char *data, unsigned int size)
{
  libbpf_set_print(libbpf_print);

  btf = btf__new(data, (__u32) size);
  if (IS_ERR(btf))
  {
    std::cerr << "BTF: failed to initialize data" << std::endl;
    btf = NULL;
    return;
  }

  state = OK;
}

BTF::BTF(unsigned char *data, unsigned int size) : btf(NULL), state(NODATA)
{
  init(data, size);
}

static unsigned char *get_data(const char *file, ssize_t *sizep)
{
  ssize_t ret;
  int fd;

  fd = open(file, O_RDONLY);
  if (fd < 0)
    return NULL;

  struct stat st;

  if (fstat(fd, &st))
  {
    close(fd);
    return NULL;
  }

  unsigned char *data;
  unsigned int size;

  size = st.st_size;

  data = (unsigned char *) malloc(size);
  if (!data)
  {
    close(fd);
    return NULL;
  }

  ret = read(fd, data, size);
  if (ret <= 0)
  {
    close(fd);
    free(data);
    return NULL;
  }

  close(fd);

  *sizep = size;
  return data;
}

BTF::BTF(void) : btf(NULL), state(NODATA)
{
  struct stat st;
  unsigned char *data;
  ssize_t size;
  const char *path_env;
  char *path;

  // Try to get BTF file from BPFTRACE_BTF env,
  // if not present, try /lib/modules/`uname -r`/btf path
  path_env = std::getenv("BPFTRACE_BTF");
  if (path_env)
  {
    path = strdup(path_env);
  }
  else
  {
    struct utsname uts;

    if (uname(&uts))
    {
      std::cerr << "BTF: failed to get uname" << std::endl;
      return;
    }

    asprintf(&path, "/lib/modules/%s/btf", uts.release);
  }

  if (!path)
  {
      std::cerr << "BTF: failed to get BTF path" << std::endl;
      return;
  }

  if (stat(path, &st))
  {
    if (bt_verbose && path_env)
      std::cerr << "BTF: wrong data path: " << path << std::endl;
    return;
  }

  data = get_data(path, &size);
  if (!data)
  {
    std::cerr << "BTF: failed to read data: " << path << std::endl;
    free(path);
    return;
  }

  init(data, size);

  free(path);
  free(data);
}

BTF::~BTF()
{
  btf__free(btf);
}

} // namespace bpftrace

#else // HAVE_LIBBPF

// TODO(jolsa) - add this to act_helpers.h and use it globaly
#define __maybe_unused __attribute__((__unused__))

namespace bpftrace {

BTF::BTF() { }

BTF::BTF(unsigned char *data __maybe_unused, unsigned int size __maybe_unused) { }

BTF::~BTF() { }

} // namespace bpftrace

#endif // HAVE_LIBBPF
