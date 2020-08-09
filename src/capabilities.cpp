#include <system_error>
#include <fstream>
#include <string>

#include <sys/capability.h>

#include "capabilities.h"

namespace {
std::system_error SYS_ERR(const std::string& msg)
{
  return std::system_error(errno, std::generic_category(), msg);
}

int get_last_cap(void)
{
  std::string cap_last_cap("/proc/sys/kernel/cap_last_cap");
  std::ifstream file(cap_last_cap);
  if (file.fail())
    throw SYS_ERR("open(" + cap_last_cap + ")");

  std::string line;
  std::getline(file, line);
  return std::stoi(line);
}
}// namespace

Capabilities::Capabilities(void)
{
  current_ = cap_get_proc();
  if (current_ == nullptr)
    throw SYS_ERR("cap_get_proc()");
  max_cap_ = get_last_cap();
}

void Capabilities::drop_to(std::vector<cap_value_t> caps)
{
  cap_t tmpcap = cap_init();
  if (tmpcap == nullptr)
    throw SYS_ERR("cap_init()");

  try
  {
    if (cap_clear(tmpcap) < 0)
      throw SYS_ERR("cap_clear()");

    if (cap_set_flag(tmpcap, CAP_EFFECTIVE, caps.size(), &caps[0], CAP_SET) < 0)
      throw SYS_ERR("cap_set_flags(CAP_EFFECTIVE)");

    if (cap_set_flag(tmpcap, CAP_PERMITTED, caps.size(), &caps[0], CAP_SET) < 0)
      throw SYS_ERR("cap_set_flags(CAP_PERMITTED)");

    if (cap_set_proc(tmpcap) < 0)
      throw SYS_ERR("cap_set_proc(" + to_string(tmpcap) + ")");

    cap_free(current_);
    current_ = tmpcap;
  }
  catch (const std::runtime_error& e)
  {
    cap_free(tmpcap);
    throw e;
  }
}

std::string Capabilities::to_string(cap_value_t cap)
{
  char * buf = cap_to_name(cap);
  if (buf == nullptr)
    throw SYS_ERR("cap_to_name()");
  std::string name(buf);
  cap_free(buf);
  return name;
}

std::string Capabilities::to_string(cap_t cap)
{
  char * buf = cap_to_text(cap, nullptr);
  if (buf == nullptr)
    return "";
  std::string str(buf);
  cap_free(buf);
  str.erase(0,2);
  return str;
}

void Capabilities::drop(cap_value_t cap)
{
  cap_t tmpcap = cap_dup(current_);
  if (tmpcap == nullptr)
    throw SYS_ERR("cap_dup()");

  try
  {
    if (cap_set_flag(tmpcap, CAP_EFFECTIVE, 1, &cap, CAP_CLEAR) < 0)
      throw SYS_ERR("cap_set_flags(CAP_EFFECTIVE)");

    if (cap_set_flag(tmpcap, CAP_PERMITTED, 1, &cap, CAP_CLEAR) < 0)
      throw SYS_ERR("cap_set_flags(CAP_PERMITTED)");

    if (cap_set_proc(tmpcap) < 0)
      throw SYS_ERR("cap_set_proc(" + to_string(cap) + ")");
  }
  catch (const std::runtime_error& e)
  {
    cap_free(tmpcap);
    throw e;
  }

  cap_free(current_);
  current_ = tmpcap;
}

bool Capabilities::system_has_cap(cap_value_t cap)
{
  return cap <= max_cap_;
}
