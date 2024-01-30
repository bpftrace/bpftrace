#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <errno.h>
#include <glob.h>
#include <libgen.h>
#include <linux/limits.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#define errExit(msg)                                                           \
  do {                                                                         \
    perror(msg);                                                               \
    exit(EXIT_FAILURE);                                                        \
  } while (0)

void mkdir_recursive(const char *path)
{
  char *subpath, *fullpath;

  fullpath = strdup(path);
  subpath = dirname(fullpath);
  if (strlen(subpath) > 1)
    mkdir_recursive(subpath);
  if (mkdir(path, 0770) != 0 && (errno != EEXIST))
    errExit("Failed to make shared dir mount");
  free(fullpath);
}

/*
Run another simple test program in a different mount namespace, to which we
have used pivot root.

usage: mountns_pivot_wrapper some_testprog

This wrapper is very similar to mountns_wrapper, but it pivots the root
before executing the program. Docker and containerd use pivot_root to
change the root of the running process.

This means that when examining the process via /proc on the host,
realpath of the executable will report paths in the mounted namespace
rather than in the host namespace.

Some common directories for system shared libraries are mounted into the new
namespace to enable running dynamically linked test executables.
*/

int main(int argc, char *argv[])
{
  const char *private_mount = "/tmp/bpftrace-unshare-mountns-pivot-test";
  char dpath[PATH_MAX];
  char exe[PATH_MAX];
  char oldroot[PATH_MAX];

  if (argc != 2)
    errExit("mountns_pivot_wrapper requires and accepts a single argument.");

  // Enter a new mount namespace
  if (unshare(CLONE_NEWNS) != 0)
    errExit("Failed to unshare");

  // Recursively set the mount namespace to private, so caller can't see
  if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) != 0)
    errExit("Failed to make mount private");

  // make a tempdir and bind mount containing testprog folder to it
  if (mkdir(private_mount, 0770) != 0 && (errno != EEXIST))
    errExit("Failed to make private mount dir");

  int idx = readlink("/proc/self/exe", dpath, sizeof(dpath) - 1);
  dpath[idx] = '\0';

  char *dname = dirname(dpath);
  if (mount(dname, private_mount, NULL, MS_BIND, NULL) != 0)
    errExit("Failed to set up private bind mount");

  /*
   * Mount directories containing system libraries, to support running of
   * dynamically linked programs after we've pivoted our root.
   */
  glob_t globbuf;
  glob("/lib*", GLOB_NOSORT, NULL, &globbuf);
  glob("/usr/lib*", GLOB_NOSORT | GLOB_APPEND, NULL, &globbuf);
  glob("/nix/store", GLOB_NOSORT | GLOB_APPEND, NULL, &globbuf);
  for (size_t i = 0; i < globbuf.gl_pathc; i++) {
    const char *global_lib_dir = globbuf.gl_pathv[i];
    char shared_dir_mount[PATH_MAX];
    snprintf(
        shared_dir_mount, PATH_MAX, "%s/%s", private_mount, global_lib_dir);

    mkdir_recursive(shared_dir_mount);

    if (mount(global_lib_dir, shared_dir_mount, NULL, MS_BIND, NULL) != 0)
      errExit("Failed to mount a system lib directory");
  }

  /*
   * Pivot root
   */
  snprintf(oldroot, PATH_MAX, "%s/%s", private_mount, "old");
  if (mkdir(oldroot, 0770) != 0 && (errno != EEXIST))
    errExit("Failed to make old root directory for pivot_root");

  if (syscall(SYS_pivot_root, private_mount, oldroot) != 0) {
    errExit("Couldn't pivot to new root");
  }

  if (chdir("/") != 0) {
    errExit("Couldn't chdir to new root");
  }

  snprintf(exe, PATH_MAX, "/%s", argv[1]);
  char *args[] = { exe, NULL };

  return execv(args[0], args);
}
