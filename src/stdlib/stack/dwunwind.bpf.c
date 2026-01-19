#define __KERNEL__
#include <vmlinux.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#include "expression.h"

#define LOG(...) // bpf_printk(__VA_ARGS__)
#define DBG(...) // bpf_printk(__VA_ARGS__)
#define INFO(...) // bpf_printk(__VA_ARGS__)
#define TABLE(...) // bpf_printk(__VA_ARGS__)

#define MAX_MAPPINGS 1000
#define MAX_MAPPINGS_BISECT_STEPS 10

#define OFFSETMAP_SIZE 262144  // 256 KB
#define MAX_OFFSETS_BISECT_STEPS 17

#define MAX_CFT_ENTRIES 1000

#define MAX_EXPRESSION_LEN 255
#define NUM_REGISTERS 17    // 16 + RIP
#define EXPR_STACK_SIZE 16

#define RSP 7
#define RIP 16
#define MAX_STACK_FRAMES 512
#define MAX_UPROBES MAX_STACK_FRAMES

#define XOL_PAGE_SIZE 4096

/*
 * General description of the lookup process:
 *
 *  1) With a given pid, see if we have a mapping table for it. If not,
 *     revert to frame-based stack unwinding.
 *     The mapping table maps the IP (vma) to the (adjusted) elf-file offset,
 *     and gives the offsetmap id and start position in the offsetmap.
 *  2) An offsetmap maps from a file offset to the cft entry, which contains
 *     the unwind ruleset for that location. Only the cft entry id is stored, as
 *     a ruleset can occur many times. This makes the representation very
 *     compact.
 *     The offsetmap for each file is split into multiple chunks, so that we
 *     can have a fixed entry size for the bpf map. In case a chunk (or the
 *     full offsetmap is smaller than the entry size, a bpf map entry can
 *     contain multiple offsetmap chunks. The offsets are stored in the mapping
 *     table.
 *     The chunk is a compact binary tree structure.
 *  3) The cft entry contains the unwind rules for the location. In case a rule
 *     involves an expression, only the expression id is registered.
 *  4) Expressions are stored in a separate map
 */

#pragma pack(1)
struct mapping {
  u64 nentries;
  struct map_entry {
    u64 vma_start;
    u64 offset;
    u32 offsetmap_id;
    u32 start_in_map;
  } entries[MAX_MAPPINGS];
};

struct offsetmap {
  u8 map[OFFSETMAP_SIZE];
};

enum register_rule_type {
  REGISTER_RULE_UNINITIALIZED = 0,
  REGISTER_RULE_UNDEFINED = 1,
  REGISTER_RULE_SAME_VALUE = 2,
  REGISTER_RULE_OFFSET = 3,
  REGISTER_RULE_VAL_OFFSET = 4,
  REGISTER_RULE_REGISTER = 5,
  REGISTER_RULE_EXPRESSION = 6,
  REGISTER_RULE_VAL_EXPRESSION = 7,
};

struct register_rule {
  enum register_rule_type rtype;
  union register_rule_data {
    u64 reg;
    u64 offset;
    u32 expression_id;
  } data;
};

enum cfa_rule_type {
  CFA_RULE_UNINITIALIZED = 0,
  CFA_RULE_REG_OFFSET = 1,
  CFA_RULE_EXPRESSION = 2,
};

struct cfa_rule {
  enum cfa_rule_type rtype;
  union cfa_rule_data {
    struct reg_offset {
      u32 reg;
      u64 offset;
    } reg_offset;
    u32 expression_id;
  } data;
};

struct cft {
  u64 arg_size;
  struct cfa_rule cfa;
  struct register_rule rules[NUM_REGISTERS];
};

struct expression {
  u8 ninstructions;
  u8 instructions[MAX_EXPRESSION_LEN];
 };
#pragma pack()

struct dwunwind_state {
  u32 tgid;
  u64 xol_base;
  uint current_reg_set;
  u64 regs_map[2 * NUM_REGISTERS];
  u64 regs_valid[2];
  u64 cfa;
  u64 stack[EXPR_STACK_SIZE];
  int steps;
};

//
// taken from parca-agent bpf code
// https://github.com/parca-dev/parca-agent/commit/a5ce7e995abf5
//
// Hack to thwart the verifier's detection of variable bounds.
//
// In recent kernels (6.8 and above) the verifier has gotten smarter
// in its tracking of variable bounds. For example, after an if statement like
// `if (v1 < v2)`,
// if it already had computed bounds for v2, it can infer bounds
// for v1 in each side of the branch (and vice versa). This means it can verify
// more programs successfully, which doesn't matter to us because our program
// was verified successfully before. Unfortunately it has a downside which
// _does_ matter to us: it increases the number of unique verifier states,
// which can cause the same instructions to be explored many times, especially
// in cases where a value is carried through a loop and possibly has
// multiple sets of different bounds on each iteration of the loop, leading to
// a combinatorial explosion. This causes us to blow out the kernel's budget of
// maximum number of instructions verified on program load (currently 1M).
//
// `opaquify32` is a no-op; thus `opaquify32(x, anything)` has the same value
// as `x`.
// However, the verifier is fortunately not smart enough to realize this,
// and will not realize the result has the same bounds as `x`, subverting the
// feature described above.
//
// For further discussion, see:
// https://lore.kernel.org/bpf/874jci5l3f.fsf@taipei.mail-host-address-is-not-set/
//
// if the verifier knows `val` is constant, you must set `seed`
// to something the verifier has no information about
// (if you don't have something handy, you can use `bpf_get_prandom_u32`).
// Otherwise, if the verifier knows bounds on `val` but not its exact value,
// it's fine to just use -1.
static __always_inline u32 opaquify32(u32 val, u32 seed) {
  // We use inline asm to make sure clang doesn't optimize it out
  asm volatile(
    "%0 ^= %1\n"
    "%0 ^= %1\n"
    : "+&r"(val)
    : "r"(seed)
  );
  return val;
}

// like opaquify32, but for u64.
static __always_inline u64 opaquify64(u64 val, u64 seed) {
  asm volatile(
    "%0 ^= %1\n"
    "%0 ^= %1\n"
    : "+&r"(val)
    : "r"(seed)
  );
  return val;
}

static __always_inline ulong opaquify_ul(ulong val, ulong seed) {
  asm volatile(
    "%0 ^= %1\n"
    "%0 ^= %1\n"
    : "+&r"(val)
    : "r"(seed)
  );
  return val;
}

/*
 * maps
 * once dynamic hashmaps are widely available, we can use those
 * instead of arrays to avoid having to pre-calculate the number
 * of entries in user space
 */
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1);   // updated from user space
  __type(key, u32);
  __type(value, struct mapping);
} dwunwind_mappings SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);  // updated from user space
  __type(key, u32);
  __type(value, struct offsetmap);
} dwunwind_offsetmaps SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);  // updated from user space
  __type(key, u32);
  __type(value, struct cft);
} dwunwind_cfts SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);  // updated from user space
  __type(key, u32);
  __type(value, struct expression);
} dwunwind_expressions SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, u32);
  __type(value, struct dwunwind_state);
} dwunwind_state_scrach SEC(".maps");


static struct map_entry *
find_mapping(struct mapping *m, u64 ip)
{
  int i;
  u32 n = m->nentries;
  if (n > MAX_MAPPINGS)
    n = MAX_MAPPINGS;

  ulong left = 0;
  ulong right = n;
  ulong mid = 0;
  for (i = 0; i < MAX_MAPPINGS_BISECT_STEPS && left < right; ++i) {
    mid = (left + right) / 2;
    mid = opaquify_ul(mid, (ulong)ip);
    if (mid >= MAX_MAPPINGS)
      break;
    struct map_entry *me = &m->entries[mid];

    DBG("bisection step %d: left %d right %d mid %d vma_start %lx",
      i, left, right, mid, me->vma_start);
    if (me->vma_start <= ip)
      left = mid + 1;
    else
      right = mid;
  }
  if (left == 0) {
    LOG("ip %lx below first vma_start", ip);
    return NULL;
  }
  --left;
  left = opaquify_ul(left, (ulong)ip);
  if (left >= MAX_MAPPINGS)
    return NULL;
  struct map_entry *me = &m->entries[left];
  INFO("ip %lx found in mapping %d: %lx", ip, left, me->vma_start);
  INFO("    obj %d off %lx map %d",
    me->offset >> 48, me->offset & 0xffffffffffff, me->offsetmap_id);
  return me;
}

// see src/dwunwind.cpp for encoding details
static u64
uw_read_key(u8 *ptr, ulong *pos)
{
  u64 key = 0;
  u8 b = ptr[(*pos)++];

  if (b <= 0xde) {
    key = (u64)b - 111;
  } else if (b == 0xdf) {
    /* 8 byte */
    key = *(u64 *)&ptr[*pos];
    *pos += 8;
  } else {
    /* 5 bit + 1 byte */
    key = ((b & 0x1f) << 8) | ptr[(*pos)++];
    /* sign extend */
    if (key & 0x1000) {
      key |= ~0x1ffful;
    }
  }

  return key;
}

static u32
uw_read_rel_ptr(u8 *ptr, ulong *pos, int *is_leaf)
{
  u32 rel_ptr = 0;
  u8 b = ptr[(*pos)++];

  if (b <= 0xcf) {
    rel_ptr = b;
    *is_leaf = 0;
  } else if (b <= 0xd7) {
    /* 3 bit + 2 byte */
    rel_ptr = ((b & 0x07) << 16) | *(u16 *)&ptr[*pos];
    *pos += 2;
    *is_leaf = 0;
  } else if (b <= 0xdf) {
    /* leaf ptr: 3 bit + 2 byte */
    rel_ptr = ((b & 0x07) << 16) | *(u16 *)&ptr[*pos];
    *pos += 2;
    *is_leaf = 1;
  } else {
    /* leaf ptr: 1 byte */
    rel_ptr = b & 0x1f;
    *is_leaf = 1;
  }
  return rel_ptr;
}

static u64
uw_read_value(u8 *ptr, ulong *pos)
{
  u64 val = 0;
  u8 b = ptr[(*pos)++];

  if (b <= 0xf6) {
    val = b;
  } else if (b == 0xf7) {
    /* 3 byte */
    val = (ptr[*pos] << 16) | (ptr[*pos + 1] << 8) | ptr[*pos + 2];
    *pos += 3;
  } else {
    /* 3 bit + 1 byte */
    val = ((b & 0x07) << 8) | ptr[(*pos)++];
  }
  return val;
}

// returns entry_id
int __noinline
find_cft(u32 offsetmap_id, u64 start_in_map, u64 search_key)
{
  struct offsetmap *om = bpf_map_lookup_elem(&dwunwind_offsetmaps, &offsetmap_id);
  if (om == NULL) {
    LOG("offsetmap lookup failed for id %d", offsetmap_id);
    return -1;
  }
  DBG("offsetmap found, id %d, start %d offset %x", offsetmap_id,
      start_in_map, search_key);
  u8 *ptr = om->map;
  int is_leaf = 0;
  u64 parent_key = 0;
  ulong pos = start_in_map;
  ulong best = -1;
  ulong depth = 0;

  while (depth++ < MAX_OFFSETS_BISECT_STEPS) {
    /* bounds check for loop */
    pos = opaquify_ul(pos, (ulong)search_key);
    best = opaquify_ul(best, (ulong)search_key);
    if (pos >= OFFSETMAP_SIZE - 15) {
      LOG("uw_read_key: pos %d out of bounds", pos);
      return -1;
    }
    u64 current_key = uw_read_key(ptr, &pos);
    TABLE(" read key %ld abs %lx at pos %d", current_key,
      current_key + parent_key, pos);
    if (current_key == 0) { /* final empty node */
      return best;
    }
    current_key += parent_key;
    current_key = opaquify_ul(current_key, (ulong)search_key);
    parent_key = current_key;

    if (is_leaf) {
      /* leaf node reached */
      break;
    }

    if (!is_leaf && ptr[pos] == 0) {
      /* unmarked leaf node */
      ++pos;
      break;
    }

    TABLE("left ptr at pos %d", pos);
    u32 rel_ptr = uw_read_rel_ptr(ptr, &pos, &is_leaf);
    if (search_key < current_key) {
      TABLE(" go left at key %lx", current_key);
      /* go to left child */
      pos += rel_ptr;
    } else {
      best = uw_read_value(ptr, &pos);
      TABLE(" go right: best %d at key %lx", best, current_key);
      /* continue with right child */
    }
  }

  if (pos >= OFFSETMAP_SIZE - 15) {
    LOG("uw_read_key: pos %d out of bounds", pos);
    return -1;
  }
  /* leaf node case */

  /* left key/value */
  u64 left_key = uw_read_key(ptr, &pos);
  u64 left_value = uw_read_value(ptr, &pos);
  TABLE(" leaf left key %lx value %d", left_key + parent_key, left_value);

  if (pos >= OFFSETMAP_SIZE - 15) {
    LOG("uw_read_key: pos %d out of bounds", pos);
    return -1;
  }
  /* own value */
  u64 own_value = uw_read_value(ptr, &pos);
  TABLE(" leaf own value %d", own_value);

  if (search_key < parent_key) {
    if (left_key != 0 && search_key >= (left_key + parent_key)) {
      TABLE(" leaf left match: key %lx value %d",
        left_key + parent_key, left_value);
      return left_value;
    }
    return best;
  }

  if (pos >= OFFSETMAP_SIZE - 15) {
    LOG("uw_read_key: pos %d out of bounds", pos);
    return -1;
  }
  /* right key/value */
  u64 right_key = uw_read_key(ptr, &pos);
  u64 right_value = uw_read_value(ptr, &pos);

  if (right_key != 0 && search_key >= (right_key + parent_key)) {
    TABLE(" leaf right match: key %lx value %d",
      right_key + parent_key, right_value);
    return right_value;
  }

  return own_value;
}

u64 __noinline
eval_expr(int expression_id, int *error)
{
  u32 zero = 0;
  struct dwunwind_state *s = bpf_map_lookup_elem(&dwunwind_state_scrach, &zero);
  if (s == NULL) {
    LOG("no scratch state");
    goto err;
  }
  u64 *o_regs = &s->regs_map[s->current_reg_set ? NUM_REGISTERS : 0];
  u64 o_regs_v = s->regs_valid[s->current_reg_set ? 1 : 0];
  struct expression *expr = bpf_map_lookup_elem(&dwunwind_expressions,
      &expression_id);
  if (expr == NULL) {
    LOG("expression id %d not found", expression_id);
    goto err;
  }
  u64 *stack = s->stack;
  unsigned long sp = 0;
  int ninstr = expr->ninstructions;
  unsigned long i = 0;
  unsigned long n = 0;
  if (ninstr > MAX_EXPR_INSTRUCTIONS) {
    LOG("expression id %d too many instructions %d",
        expression_id, ninstr);
    goto err;
  }
  for (int n = 0; n < ninstr; ++n) {
    /*
     * all bounds checks upfront to reduce the number of branches
     */
    i = opaquify_ul(i, (ulong)expression_id);
    if (i >= MAX_EXPRESSION_LEN - 10) {
      LOG(" eval expr: instruction pointer out of bounds");
      goto err;
    }
    u8 instr = expr->instructions[i];
    u64 a1 = 0;
    u64 a2 = 0;
    ++i;
    if ((instr & 0xc0) == 0x40) {
      // one 8 bit argument, register
      a1 = expr->instructions[i++];
    } else if ((instr & 0xc0) == 0x80) {
      // one 64 bit argument
      a1 = *(u64 *)&expr->instructions[i];
      i += 8;
    } else if ((instr & 0xc0) == 0xc0) {
      // one 8 bit and one 64 bit argument
      a1 = expr->instructions[i++];
      a2 = *(u64 *)&expr->instructions[i];
      i += 8;
    }

    sp = opaquify_ul(sp, (ulong)expression_id);
    if (sp >= EXPR_STACK_SIZE) {
      LOG(" eval expr: stack overflow");
      goto err;
    }

    switch (instr) {
      case EXPR_OP_AND:
      case EXPR_OP_SHL:
      case EXPR_OP_GE:
      case EXPR_OP_PLUS:
      case EXPR_OP_MUL:
        if (sp < 2) {
          LOG(" eval expr: stack underflow in %d", instr);
          goto err;
        }
        break;
      case EXPR_OP_DEREF:
      case EXPR_OP_PLUS_CONST:
        if (sp < 1) {
          LOG(" eval expr: stack underflow in %d", instr);
          goto err;
        }
        break;
    }

    DBG(" eval expr id %d instr %d op %x sp %d a1 %lx a2 %lx",
        expression_id, i, instr, sp, a1, a2);
    switch (instr) {
      case EXPR_OP_CONST:
        stack[sp++] = a1;
        break;
      case EXPR_OP_BREG:
        if (a1 >= NUM_REGISTERS) {
          LOG(" eval expr: invalid register number %d", (int)a1);
          goto err;
        }
        if ((o_regs_v & (1 << a1)) == 0) {
          LOG(" eval expr: register %d not valid", (int)a1);
          goto err;
        }
        stack[sp++] = o_regs[a1] + a2;
        break;
      case EXPR_OP_AND:
        stack[sp - 2] = stack[sp - 2] & stack[sp - 1];
        --sp;
        break;
      case EXPR_OP_SHL:
        stack[sp - 2] = stack[sp - 2] << stack[sp - 1];
        --sp;
        break;
      case EXPR_OP_GE:
        stack[sp - 2] = (stack[sp - 2] >= stack[sp - 1]) ? 1 : 0;
        --sp;
        break;
      case EXPR_OP_PLUS:
        stack[sp - 2] = stack[sp - 2] + stack[sp - 1];
        --sp;
        break;
      case EXPR_OP_MUL:
        stack[sp - 2] = stack[sp - 2] * stack[sp - 1];
        --sp;
        break;
      case EXPR_OP_PLUS_CONST:
        stack[sp - 1] = stack[sp - 1] + a1;
        break;
      case EXPR_OP_DEREF: {
          u64 addr = stack[--sp];
          u64 val = 0;
          int ret = bpf_probe_read_user(&val, sizeof(val), (void *)addr);
          if (ret < 0) {
            LOG(" eval expr: failed to deref addr %lx", addr);
            goto err;
          }
          stack[sp++] = val;
        break;
      }
      default:
        LOG(" eval expr: unsupported op %x", instr);
        goto err;
    }
  }

  if (sp == 0) {
    LOG(" eval expr: empty stack at end");
    goto err;
  }

  if (sp > 16) {
    LOG(" eval expr: stack overflow at end, sp %d", sp);
    goto err;
  }
  LOG(" returning %lx", stack[sp - 1]);
  return stack[sp - 1];

err:
  if (error != NULL)
    *error = 1;
  return 0;
}

u64 recover_uretprobe_addr(u64 rsp)
{
  struct task_struct *task = bpf_get_current_task_btf();
  struct uprobe_task *up = BPF_CORE_READ(task, utask);
  struct return_instance *ri = BPF_CORE_READ(up, return_instances);

  for (int i = 0; i < MAX_UPROBES; ++i) {
    if (ri == NULL) {
      LOG("no match upretprobe found");
      return 0;
    }
    u64 stack = BPF_CORE_READ(ri, stack);
    u64 retaddr = BPF_CORE_READ(ri, orig_ret_vaddr);
    LOG("uretprobe: rsp %lx stack %lx retaddr %lx", rsp, stack, retaddr);
    if (stack + 8 == rsp) {
      return retaddr;
    }
    ri = BPF_CORE_READ(ri, next);
  }

  return 0;
}

int
unwind_step(void)
{
  // fetch state from scratch memory
  u32 zero = 0;
  struct dwunwind_state *s = bpf_map_lookup_elem(&dwunwind_state_scrach, &zero);
  if (s == NULL) {
    LOG("no scratch state");
    return 1;
  }

  /*
   * load mapping for pid
   * eventually we might want to use bpf_find_vma if it is widely available
   */
  struct mapping *m = bpf_map_lookup_elem(&dwunwind_mappings, &s->tgid);
  if (m == NULL) {
    INFO("no mapping found");
    return 1;
  }

  u64 *regs_o;    /* regs, old set */
  u64 *regs_n;    /* regs, new set */
  u64 regs_v_o;  /* regs valid, old set */
  u64 regs_v_n;  /* regs valid, new set */

  if (s->current_reg_set == 0) {
    regs_v_o = s->regs_valid[0];
    regs_n = &s->regs_map[NUM_REGISTERS];
    regs_o = &s->regs_map[0];
  } else {
    regs_v_o = s->regs_valid[1];
    regs_n = &s->regs_map[0];
    regs_o = &s->regs_map[NUM_REGISTERS];
  }
  regs_v_n = regs_v_o;

  if ((regs_v_o & (1 << RIP)) == 0) {
    INFO("Stack walk: PC is None, stopping");
    return 1;
  }

  struct map_entry *me = find_mapping(m, regs_o[RIP]);
  if (me == NULL) {
    LOG("no map entry found");
    return 1;
  }

  u64 offset = regs_o[RIP] - me->vma_start + me->offset;
  DBG("rip %lx vma_start %lx offset %lx", regs_o[RIP], me->vma_start, offset);
  int cft_id;
  [[clang::noinline]] cft_id = find_cft(me->offsetmap_id, me->start_in_map, offset);
  INFO(" found cft entry id %d", cft_id);

  if (cft_id < 0) {
    LOG("error in offsetmap processing");
    return 1;
  }
  if (cft_id == 0) {
    LOG("no offsetmap entry found for ip %lx offset %lx", regs_o[RIP], offset);
    return 1;
  }

  struct cft *cf = bpf_map_lookup_elem(&dwunwind_cfts, &cft_id);
  if (cf == NULL) {
    LOG("cft not found");
    return 1;
  }
  INFO("cft %d found", cft_id);

  /* compute CFA */
  u64 cfa;
  if (cf->cfa.rtype == CFA_RULE_UNINITIALIZED) {
    LOG("Stack walk: CFA uninitialized, stopping");
    return 1;
  } else if (cf->cfa.rtype == CFA_RULE_EXPRESSION) {
    int error = 0;
    [[clang::noinline]] cfa = eval_expr(cf->cfa.data.expression_id, &error);
    INFO("eval_expr cft_id %d ip %lx", cft_id, regs_o[RIP]);
    INFO("step %d CFA = %lx error %d", s->steps, cfa, error);
    if (error != 0)
      return 1;
  } else if (cf->cfa.rtype == CFA_RULE_REG_OFFSET) {
    u32 r = cf->cfa.data.reg_offset.reg;
    s64 o = cf->cfa.data.reg_offset.offset;
    if ((regs_v_o & (1 << r)) == 0) {
      LOG("Stack walk: CFA register r%d not valid, stopping", r);
      return 1;
    }
    if (r >= NUM_REGISTERS) {
      LOG("Stack walk: CFA register r%d out of range, stopping", r);
      return 1;
    }
    cfa = regs_o[r] + o;
    INFO("  CFA = r%d (%lx) + %lld = %lx", r, regs_o[r], o);
    INFO("  new CFA = %lx", cfa);
  } else {
    LOG("Stack walk: unknown CFA rule type %d, stopping", cf->cfa.rtype);
    return 1;
  }

  // unwind stack pointer
  regs_o[RSP] = cfa;
  regs_n[RSP] = cfa;
  s->cfa = cfa;

  for (int reg = 0; reg < NUM_REGISTERS; ++reg) {
    regs_v_n = opaquify_ul(regs_v_n, (ulong)cft_id);
    if (cf->rules[reg].rtype == REGISTER_RULE_UNINITIALIZED ||
        cf->rules[reg].rtype == REGISTER_RULE_SAME_VALUE) {
      // register is unchanged
      regs_n[reg] = regs_o[reg];
      DBG("  r%d: same value %lx", reg, regs_n[reg]);
    } else if (cf->rules[reg].rtype == REGISTER_RULE_UNDEFINED) {
      // register is undefined
      DBG("  r%d: undefined", reg);
      regs_v_n &= ~(1 << reg);
    } else if (cf->rules[reg].rtype == REGISTER_RULE_OFFSET) {
      // register is at CFA + offset
      s64 off = cf->rules[reg].data.offset;
      u64 addr = cfa + off;
      // read value from user stack
      u64 val = 0;
      int ret = bpf_probe_read_user(&val, sizeof(val), (void *)addr);
      if (ret < 0) {
        LOG("Stack walk: failed to read r%d at addr %lx",
          reg, addr);
        return 1;
      }
      DBG("  r%d: at addr %lx value %lx", reg, addr, val);
      regs_n[reg] = val;
      regs_v_n |= (1 << reg);
    } else {
      LOG("Stack walk: unsupported register rule type %d for r%d",
        cf->rules[reg].rtype, reg);
      return 1;
    }
  }

  if (regs_n[RIP] >= s->xol_base && regs_n[RIP] < s->xol_base + XOL_PAGE_SIZE) {
    // in xol page, adjust to return address
    u64 rec;
    [[clang::noinline]] rec = recover_uretprobe_addr(regs_n[RSP]);
    if (rec != 0)
      regs_n[RIP] = rec;
  }

  // adjust recovered IP to fall into previous instruction
  // this is not valid for signal frames, but we don't have this
  // information yet.
  regs_n[RIP] -= 1;

  // switch reg set
  s->current_reg_set = !s->current_reg_set;
  s->regs_valid[s->current_reg_set ? 1 : 0] = regs_v_n;

  INFO("After unwind step: next PC %lx", regs_n[RIP]);

  s->steps += 1;
  return 0;
}

long __ustack_dwunwind(void *ctx, u64 *buf, u32 buf_size, u32 tgid)
{
  struct task_struct *task;

  u64 *buf_start = buf;

  /* test if we have a mapping for this pid, otherwise fall back to ustack() */
  void *m = bpf_map_lookup_elem(&dwunwind_mappings, &tgid);
  if (m == NULL)
    return bpf_get_stack(ctx, buf, buf_size, BPF_F_USER_STACK);

  task = bpf_get_current_task_btf();
  if (task == NULL) {
    LOG("no task struct");
    return 0;
  }

  struct mm_struct *mm = BPF_CORE_READ(task, mm);
  if (mm == NULL) {
    LOG("no mm struct");
    return 0;
  }
  u64 stack_top = BPF_CORE_READ(mm, start_stack);
  INFO("start stack: %lx", stack_top);

  /* find uprobes xol page to be able to walk through uretprobes */
  struct xol_area *xol_area = BPF_CORE_READ(mm, uprobes_state.xol_area);
  u64 xol_base = BPF_CORE_READ(xol_area, vaddr);
  INFO("xol base: %lx", xol_base);

  /*
   * user mode regs are passed in as ctx. We fetch
   * them anyway, so that it also works when called from
   * kernel probes
   */
  struct pt_regs *pregs = (struct pt_regs *)bpf_task_pt_regs(task);
  if (pregs == NULL) {
    LOG("no pt_regs");
    return 0;
  }
  // XXX differentiate between 32 and 64 bit?

  u32 zero = 0;
  struct dwunwind_state *s = bpf_map_lookup_elem(&dwunwind_state_scrach, &zero);
  if (s == NULL) {
    LOG("no scratch state");
    return 1;
  }
  s->tgid = tgid;
  s->xol_base = xol_base;

  // XXX just read all as a block and sort later?
  // XXX not all needed for stack walk without params
  s->regs_map[0] = BPF_CORE_READ(pregs, ax);
  s->regs_map[1] = BPF_CORE_READ(pregs, dx);
  s->regs_map[2] = BPF_CORE_READ(pregs, cx);
  s->regs_map[3] = BPF_CORE_READ(pregs, bx);
  s->regs_map[4] = BPF_CORE_READ(pregs, si);
  s->regs_map[5] = BPF_CORE_READ(pregs, di);
  s->regs_map[6] = BPF_CORE_READ(pregs, bp);
  s->regs_map[7] = BPF_CORE_READ(pregs, sp);
  s->regs_map[8] = BPF_CORE_READ(pregs, r8);
  s->regs_map[9] = BPF_CORE_READ(pregs, r9);
  s->regs_map[10] = BPF_CORE_READ(pregs, r10);
  s->regs_map[11] = BPF_CORE_READ(pregs, r11);
  s->regs_map[12] = BPF_CORE_READ(pregs, r12);
  s->regs_map[13] = BPF_CORE_READ(pregs, r13);
  s->regs_map[14] = BPF_CORE_READ(pregs, r14);
  s->regs_map[15] = BPF_CORE_READ(pregs, r15);
  s->regs_map[16] = BPF_CORE_READ(pregs, ip);
  INFO("rsp %lx ip %lx r8 %lx",
    s->regs_map[7], s->regs_map[16], s->regs_map[8]);

  INFO("tgid %d", tgid);

  s->current_reg_set = 0;
  s->regs_valid[0] = 0x1ffff;
  s->steps = 0;

  if (buf_size < 8) {
    LOG("buffer too small");
    return 0;
  }

  *buf++ = s->regs_map[RIP];
  int nframes = buf_size / sizeof(u64);
  for (int i = 1; i < MAX_STACK_FRAMES && i < nframes; ++i) {
    [[clang::noinline]] if (unwind_step() != 0)
      goto done;
    ulong off = s->current_reg_set == 1 ? NUM_REGISTERS : 0;
    INFO("frame %d: RIP %lx RSP %lx", i,
      s->regs_map[RIP + off], s->regs_map[RSP + off]);
    if (s->regs_map[RSP + off] >= stack_top - 8) {
      INFO("top of stack reached");
      goto done;
    }
    *buf++ = s->regs_map[RIP + off];
  }

done:
  INFO("walked %d steps", s->steps);
  INFO("\n");
  return (u64)buf - (u64)buf_start;
}
