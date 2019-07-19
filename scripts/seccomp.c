// Compile with gcc seccomp.c -lseccomp -ggdb -o seccomp

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <linux/bpf.h>
#include <seccomp.h>

void help() {
  printf("Simulate bpf(2) syscall failures based on the bpf(2) command ");
  printf("executed\n");
  printf("\n");
  printf("USAGE:\n");
  printf("./seccomp [OPTIONS] -- command [args]");
  printf("./seccomp -e map_create:11 -- bpftrace -e ...\n");
  printf("./seccomp -e map_create:100 -k prog_load  -- ./src/bpftrace -e ");
  printf("'i:s:1 { @=5 }'\n");
  printf("\n");
  printf("OPTIONS:\n");
  printf("\t-k [NAME] Kill program when bpf is called with this command\n");
  printf("\t-e [NAME]:[ERRNO] Set errno to ERRNO program when bpf is called ");
  printf("with this command\n");
  printf("\t-l List known bpf commands\n");
  printf("\n");
  exit(0);
}

struct entry {
  const int value;
  const char* symbol;
  const char* name;
};

#define ENTRY(symbol, name) \
  { symbol, #symbol, name }

static const struct entry bpf_commands[] = {
    ENTRY(BPF_MAP_CREATE, "map_create"),
    ENTRY(BPF_MAP_LOOKUP_ELEM, "map_lookup_elem"),
    ENTRY(BPF_MAP_UPDATE_ELEM, "map_update_elem"),
    ENTRY(BPF_MAP_DELETE_ELEM, "map_delete_elem"),
    ENTRY(BPF_MAP_GET_NEXT_KEY, "map_get_next_key"),
    ENTRY(BPF_PROG_LOAD, "prog_load"),
    ENTRY(BPF_OBJ_PIN, "obj_pin"),
    ENTRY(BPF_OBJ_GET, "obj_get"),
    ENTRY(BPF_PROG_ATTACH, "prog_attach"),
    ENTRY(BPF_PROG_DETACH, "prog_detach"),
    ENTRY(BPF_PROG_TEST_RUN, "prog_test_run"),
    ENTRY(BPF_PROG_GET_NEXT_ID, "prog_get_next_id"),
    ENTRY(BPF_MAP_GET_NEXT_ID, "map_get_next_id"),
    ENTRY(BPF_PROG_GET_FD_BY_ID, "prog_get_fd_by_id"),
    ENTRY(BPF_MAP_GET_FD_BY_ID, "map_get_fd_by_id"),
    ENTRY(
        BPF_OBJ_GET_INFO_BY_FD,
        "obj_get_info_by_fd"),
    ENTRY(BPF_PROG_QUERY, "prog_query"),
    ENTRY(BPF_RAW_TRACEPOINT_OPEN,
          "raw_tracepoint_open"),
    ENTRY(BPF_BTF_LOAD, "btf_load"),
    ENTRY(BPF_BTF_GET_FD_BY_ID, "btf_get_fd_by_id"),
    ENTRY(BPF_TASK_FD_QUERY, "task_fd_query"),
};

void list(void) {
  for (int x = 0; x < sizeof(bpf_commands) / sizeof(struct entry); x++) {
    printf(
        "name: %s\tflag: %s\n", bpf_commands[x].name, bpf_commands[x].symbol);
  }
  exit(0);
}

// Search the bpf_commands table for an entry for with symbol or name matches
// the agument name
//
// Return the bpf command value or -1 if the lookup failed
int lookup_cmd(char* name) {
  for (int x = 0; x < sizeof(bpf_commands) / sizeof(struct entry); x++) {
    if (strcmp(name, bpf_commands[x].name) == 0 ||
        strcmp(name, bpf_commands[x].symbol) == 0) {
      return bpf_commands[x].value;
    }
  }
  return -1;
}

// Parse the errno string and add the required filter to seccomp
int add_errno(scmp_filter_ctx* ctx, char* str) {
  assert(ctx != NULL);
  assert(str != NULL);
  char* substr = strchr(str, ':');
  if (substr == NULL) {
    printf("Expected ERRNO format \"COMMAND:ERRNO\", got: %s\n", str);
    return -1;
  }

  // Copy command to a new string
  int keysize = substr - str;
  char* buf = malloc((keysize + 1) * sizeof(char));
  assert(buf != NULL);
  strncpy(buf, str, keysize);
  // convert ERRNO to postive int
  int err = atoi(substr + 1);
  if (err < 0) {
    err *= -1;
  }

  // Find the command ID
  int command = lookup_cmd(buf);
  if (command < 0) {
    printf("Unknown bpf command: %s\n", buf);
    goto exit;
  }

  int rc = seccomp_rule_add(*ctx,
                            SCMP_ACT_ERRNO(err),
                            SCMP_SYS(bpf),
                            1,
                            SCMP_A0(SCMP_CMP_EQ, command));

  if (rc < 0) {
    printf("Failed to add ERRNO(%d) filter for command: %s(%d): %s\n",
           err,
           buf,
           command,
           strerror(rc * -1));
  } else {
    printf("Added ERRNO(%d) for command: %s(%d)\n", err, buf, command);
  }

exit:
  free(buf);
}

// Parse CLI args, setup seccomp and execve into the command
int main(int argc, char** argv) {
  int index;
  int c;

  opterr = 0;

  scmp_filter_ctx ctx;
  ctx = seccomp_init(SCMP_ACT_ALLOW);
  if (ctx == NULL) {
    printf("Failed to init seccomp\n");
  }

  while ((c = getopt(argc, argv, "k:e:hl")) != -1) {
    switch (c) {
    case 'h':
      help();
      break;
    case 'l':
      list();
      break;
    case 'k': {
      int v = lookup_cmd(optarg);
      if (v >= 0) {
        int rc = seccomp_rule_add(
            ctx, SCMP_ACT_KILL, SCMP_SYS(bpf), 1, SCMP_A0(SCMP_CMP_EQ, v));
        if (rc < 0) {
          printf("Failed to add KILL filter for command: %s: %s\n",
                 optarg,
                 strerror(-1 * rc));
        } else {
          printf("Added KILL for command: %s\n", optarg);
        }
      } else {
        printf("Unknown bpf command: %s\n", optarg);
      }
      break;
    }
    case 'e':
      add_errno(&ctx, optarg);
      break;
    default:
      printf("Unknown option: %s\n", optarg);
      break;
    }
  }

  if (argc - optind < 2) {
    printf("expected command with arguments\n");
    goto abort;
  }

  seccomp_load(ctx);
  printf("Executing: ");
  for (int i = optind; i < argc; i++) {
    printf("%s ", argv[i]);
  }
  printf("\n------------\n\n");

  int rc = execve(argv[optind], argv + optind, NULL);
  printf("Execve failed: %d, %s\n", rc, strerror(errno));

abort:
  seccomp_release(ctx);
}
