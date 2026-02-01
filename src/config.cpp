#include <algorithm>
#include <cstring>
#include <fstream>
#include <sstream>
#include <unordered_set>

#include "config.h"
#include "log.h"
#include "types.h"
#include "util/int_parser.h"
#include "util/strings.h"

namespace bpftrace {

char ParseError::ID;
char RenameError::ID;
char LicenseError::ID;

void ParseError::log(llvm::raw_ostream &OS) const
{
  OS << key_ << ": " << detail_;
}

void RenameError::log(llvm::raw_ostream &OS) const
{
  OS << "key has been renamed to '" << name_ << "'";
}

static const std::unordered_map<std::string, CompatibleBPFLicense>
    BPF_LICENSE_STR = { { "GPL", GPL },
                        { "GPL v2", GPL_V2 },
                        { "GPL and additional rights", GPL_AR },
                        { "Dual BSD/GPL", DUAL_BSD_GPL },
                        { "Dual MIT/GPL", DUAL_MIT_GPL },
                        { "Dual MPL/GPL", DUAL_MPL_GPL } };

void LicenseError::log(llvm::raw_ostream &OS) const
{
  OS << "Invalid value for license. Found: " << license() << ". Valid values: ";
  bool first = true;
  for (const auto &[k, v] : BPF_LICENSE_STR) {
    if (!first) {
      OS << ", ";
    }
    OS << k;
    first = false;
  }
  OS << ". Read more about BPF programs and licensing: "
        "https://docs.kernel.org/bpf/"
        "bpf_licensing.html#using-bpf-programs-in-the-linux-kernel";
}

// /proc/sys/kernel/randomize_va_space >= 1
static bool is_aslr_enabled()
{
  std::string randomize_va_space_file = "/proc/sys/kernel/randomize_va_space";

  {
    std::ifstream file(randomize_va_space_file);
    if (file.fail()) {
      LOG(V1) << std::strerror(errno) << ": " << randomize_va_space_file;
      // conservatively return true
      return true;
    }

    std::string line;
    if (std::getline(file, line) && std::stoi(line) < 1)
      return false;
  }

  return true;
}

Config::Config(bool has_cmd)
    : user_symbol_cache_type((has_cmd || !is_aslr_enabled())
                                 ? UserSymbolCacheType::per_program
                                 : UserSymbolCacheType::per_pid) {};

template <>
struct ConfigParser<uint64_t> {
  Result<OK> parse(const std::string &key,
                   uint64_t *target,
                   const std::string &s)
  {
    // If this can be parsed as a literal integer, then we take that.
    auto val = util::to_uint(s);
    if (!val) {
      return make_error<ParseError>(key, "expecting a number, got " + s);
    }
    *target = *val;
    return OK();
  }
  Result<OK> parse([[maybe_unused]] const std::string &key,
                   uint64_t *target,
                   uint64_t v)
  {
    *target = v;
    return OK();
  }
};

template <>
struct ConfigParser<bool> {
  Result<OK> parse(const std::string &key,
                   bool *target,
                   const std::string &original)
  {
    if (util::is_str_bool_truthy(original)) {
      *target = true;
      return OK();
    } else if (util::is_str_bool_falsy(original)) {
      *target = false;
      return OK();
    } else {
      return make_error<ParseError>(
          key, "Invalid bool value: valid values are true, false, 1 or 0.");
    }
  }
  Result<OK> parse([[maybe_unused]] const std::string &key,
                   bool *target,
                   uint64_t v)
  {
    if (v != 0) {
      *target = true;
      return OK();
    } else {
      *target = false;
      return OK();
    }
  }
};

template <>
struct ConfigParser<std::string> {
  Result<OK> parse([[maybe_unused]] const std::string &key,
                   std::string *target,
                   const std::string &s)
  {
    *target = s;
    return OK();
  }
  Result<OK> parse([[maybe_unused]] const std::string &key,
                   std::string *target,
                   uint64_t v)
  {
    std::stringstream ss;
    ss << v;
    *target = ss.str();
    return OK();
  }
};

template <>
struct ConfigParser<UserSymbolCacheType> {
  Result<OK> parse(const std::string &key,
                   UserSymbolCacheType *target,
                   const std::string &original)
  {
    std::string s = util::to_lower(original);
    if (s == "1") {
      return OK(); // Leave as the default.
    } else if (s == "per_pid") {
      *target = UserSymbolCacheType::per_pid;
      return OK();
    } else if (s == "per_program") {
      *target = UserSymbolCacheType::per_program;
      return OK();
    } else if (s == "none" || s == "0") {
      *target = UserSymbolCacheType::none;
      return OK();
    } else {
      return make_error<ParseError>(
          key,
          "Invalid value for cache_user_symbols: valid values are PER_PID, "
          "PER_PROGRAM, and NONE.");
    }
  }
  Result<OK> parse([[maybe_unused]] const std::string &key,
                   UserSymbolCacheType *target,
                   uint64_t v)
  {
    if (v == 0) {
      *target = UserSymbolCacheType::none;
      return OK();
    } else {
      // Leave as the default.
      return OK();
    }
  }
};

template <>
struct ConfigParser<ConfigMissingProbes> {
  Result<OK> parse(const std::string &key,
                   ConfigMissingProbes *target,
                   const std::string &original)
  {
    std::string s = util::to_lower(original);
    if (s == "ignore") {
      *target = ConfigMissingProbes::ignore;
      return OK();
    } else if (s == "warn") {
      *target = ConfigMissingProbes::warn;
      return OK();
    } else if (s == "error") {
      *target = ConfigMissingProbes::error;
      return OK();
    } else {
      return make_error<ParseError>(key,
                                    "Invalid value for missing_probes: valid "
                                    "values are ignore, warn, and error.");
    }
  }
  Result<OK> parse(const std::string &key,
                   [[maybe_unused]] ConfigMissingProbes *target,
                   [[maybe_unused]] uint64_t v)
  {
    return make_error<ParseError>(key,
                                  "Invalid value for missing_probes: valid "
                                  "values are ignore, warn, and error.");
  }
};

template <>
struct ConfigParser<CompatibleBPFLicense> {
  Result<OK> parse([[maybe_unused]] const std::string &key,
                   CompatibleBPFLicense *target,
                   const std::string &original)
  {
    auto found = BPF_LICENSE_STR.find(original);
    if (found == BPF_LICENSE_STR.end()) {
      return make_error<LicenseError>(original);
    }

    *target = found->second;
    return OK();
  }
  Result<OK> parse([[maybe_unused]] const std::string &key,
                   [[maybe_unused]] CompatibleBPFLicense *target,
                   uint64_t v)
  {
    return make_error<LicenseError>(std::to_string(v));
  }
};

template <>
struct ConfigParser<ConfigUnstable> {
  Result<OK> parse(const std::string &key,
                   ConfigUnstable *target,
                   const std::string &original)
  {
    std::string s = util::to_lower(original);
    if (s == "enable" || util::is_str_bool_truthy(original)) {
      *target = ConfigUnstable::enable;
      return OK();
    } else if (s == "warn") {
      *target = ConfigUnstable::warn;
      return OK();
    } else if (s == "error" || util::is_str_bool_falsy(original)) {
      *target = ConfigUnstable::error;
      return OK();
    } else {
      return make_error<ParseError>(key,
                                    "Invalid value for unstable config: valid "
                                    "values are enable, warn, and error.");
    }
  }
  Result<OK> parse([[maybe_unused]] const std::string &key,
                   [[maybe_unused]] ConfigUnstable *target,
                   [[maybe_unused]] uint64_t v)
  {
    if (v != 0) {
      *target = ConfigUnstable::enable;
      return OK();
    } else {
      *target = ConfigUnstable::error;
      return OK();
    }
  }
};

struct AnyParser {
  using KeyType = const std::string &;
  std::function<Result<OK>(KeyType, Config *, uint64_t)> integer;
  std::function<Result<OK>(KeyType, Config *, const std::string &)> string;
};

template <typename T>
AnyParser parser(T fn)
{
  // The passed function should return a pointer to the field. We extract
  // the type of the returned field, and match against the parser.
  using R = std::remove_pointer_t<decltype(fn(static_cast<Config *>(nullptr)))>;
  return AnyParser{
    .integer =
        [fn](const std::string &k, Config *c, uint64_t value) {
          ConfigParser<R> parser;
          return parser.parse(k, fn(c), value);
        },
    .string =
        [fn](const std::string &k, Config *c, const std::string &s) {
          ConfigParser<R> parser;
          return parser.parse(k, fn(c), s);
        },
  };
}

// This map construsts all the different parsers.
#define CONFIG_FIELD_PARSER(x) parser([](Config *config) { return &config->x; })
const std::map<std::string, AnyParser> CONFIG_KEY_MAP = {
  { "cache_user_symbols", CONFIG_FIELD_PARSER(user_symbol_cache_type) },
  { "cpp_demangle", CONFIG_FIELD_PARSER(cpp_demangle) },
  { "lazy_symbolication", CONFIG_FIELD_PARSER(lazy_symbolication) },
  { "license", CONFIG_FIELD_PARSER(license) },
  { "log_size", CONFIG_FIELD_PARSER(log_size) },
  { "max_bpf_progs", CONFIG_FIELD_PARSER(max_bpf_progs) },
  { "max_cat_bytes", CONFIG_FIELD_PARSER(max_cat_bytes) },
  { "max_map_keys", CONFIG_FIELD_PARSER(max_map_keys) },
  { "max_probes", CONFIG_FIELD_PARSER(max_probes) },
  { "max_strlen", CONFIG_FIELD_PARSER(max_strlen) },
  { "on_stack_limit", CONFIG_FIELD_PARSER(on_stack_limit) },
  { "perf_rb_pages", CONFIG_FIELD_PARSER(perf_rb_pages) },
  { "stack_mode", CONFIG_FIELD_PARSER(stack_mode) },
  { "str_trunc_trailer", CONFIG_FIELD_PARSER(str_trunc_trailer) },
  { "missing_probes", CONFIG_FIELD_PARSER(missing_probes) },
  { "print_maps_on_exit", CONFIG_FIELD_PARSER(print_maps_on_exit) },
  { "use_blazesym", CONFIG_FIELD_PARSER(use_blazesym) },
  { "show_debug_info", CONFIG_FIELD_PARSER(show_debug_info) },
  { UNSTABLE_IMPORT, CONFIG_FIELD_PARSER(unstable_import) },
  { UNSTABLE_IMPORT_STATEMENT, CONFIG_FIELD_PARSER(unstable_import_statement) },
  { UNSTABLE_MAP_DECL, CONFIG_FIELD_PARSER(unstable_map_decl) },
  { UNSTABLE_TSERIES, CONFIG_FIELD_PARSER(unstable_tseries) },
  { UNSTABLE_ADDR, CONFIG_FIELD_PARSER(unstable_addr) },
  { UNSTABLE_TYPEINFO, CONFIG_FIELD_PARSER(unstable_typeinfo) },
};

// These symbols are deprecated, and have been remapped elsewhere.
const std::map<std::string, std::string> DEPRECATED = {
  { "strlen", "max_strlen" },
  { "no_cpp_demangle", "cpp_demangle" },
  { "cat_bytes_max", "max_cat_bytes" },
  { "map_keys_max", "max_map_keys" },
};

// These are configuration names that are consumed elsewhere. We use this only
// to check if we should produce a more helpful error for the user.
const std::unordered_set<std::string> ENV_ONLY = {
  "btf",
  "kernel_build",
  "kernel_source",
  "vmlinux",
};

// This is applied for all environment variables, and will also be accepted
// as part of the general configuration key (in lower case only).
static const std::string ENV_PREFIX = "bpftrace_";

static std::string restore(const std::string &original_key)
{
  std::string key = util::to_lower(original_key);
  if (key.starts_with(ENV_PREFIX)) {
    key = key.substr(ENV_PREFIX.length());
  }
  return key;
}

static Result<AnyParser> lookup(const std::string &original_key)
{
  auto key = restore(original_key);
  auto it = CONFIG_KEY_MAP.find(key);
  if (it == CONFIG_KEY_MAP.end()) {
    auto dep = DEPRECATED.find(key);
    if (dep != DEPRECATED.end()) {
      return make_error<RenameError>(dep->second);
    }
    auto env = ENV_ONLY.find(key);
    if (env != ENV_ONLY.end()) {
      return make_error<ParseError>(
          original_key, "can only be set as an environment variable");
    }
    return make_error<ParseError>(original_key,
                                  "not a known configuration option");
  }

  return it->second;
}

Result<OK> Config::set(const std::string &original_key, const std::string &val)
{
  auto parser = lookup(original_key);
  if (!parser) {
    return parser.takeError();
  }
  return parser->string(original_key, this, val);
}

Result<OK> Config::set(const std::string &original_key, uint64_t val)
{
  auto parser = lookup(original_key);
  if (!parser) {
    return parser.takeError();
  }
  return parser->integer(original_key, this, val);
}

bool Config::is_unstable(const std::string &original_key)
{
  const static std::string UNSTABLE_PREFIX = "unstable_";
  auto key = restore(original_key);
  return key.starts_with(UNSTABLE_PREFIX);
}

Result<OK> Config::load_environment()
{
  // Scan all known keys by their environment variable name, and if it is
  // present then set from the environment value.
  for (const auto &[key, _] : CONFIG_KEY_MAP) {
    std::string env = ENV_PREFIX + key;
    std::ranges::transform(env, env.begin(), [](unsigned char c) {
      return std::toupper(c);
    });
    const auto *cenv = getenv(env.c_str());
    if (cenv) {
      auto ok = set(key, std::string(cenv));
      if (!ok) {
        return ok.takeError();
      }
    }
  }
  return OK();
}

std::string Config::get_license_str(CompatibleBPFLicense license)
{
  for (const auto &[k, v] : BPF_LICENSE_STR) {
    if (v == license) {
      return k;
    }
  }
  LOG(BUG) << "License enum not in BPF_LICENSE_STR map";
  return "";
}

} // namespace bpftrace
