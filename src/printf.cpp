#include <regex>

#include "printf.h"
#include "printf_format_types.h"
#include "struct.h"

namespace bpftrace {

std::string verify_format_string(const std::string &fmt, std::vector<Field> args)
{
  std::stringstream message;

  auto tokens_begin = std::sregex_iterator(fmt.begin(),
                                           fmt.end(),
                                           format_specifier_re);
  auto tokens_end = std::sregex_iterator();

  auto num_tokens = std::distance(tokens_begin, tokens_end);
  int num_args = args.size();
  if (num_args < num_tokens)
  {
    message << "printf: Not enough arguments for format string (" << num_args
            << " supplied, " << num_tokens << " expected)" << std::endl;
    return message.str();
  }
  if (num_args > num_tokens)
  {
    message << "printf: Too many arguments for format string (" << num_args
            << " supplied, " << num_tokens << " expected)" << std::endl;
    return message.str();
  }

  auto token_iter = tokens_begin;
  for (int i=0; i<num_args; i++, token_iter++)
  {
    Type arg_type = args.at(i).type.type;
    if (arg_type == Type::ksym || arg_type == Type::usym ||
        arg_type == Type::probe || arg_type == Type::username ||
        arg_type == Type::kstack || arg_type == Type::ustack ||
        arg_type == Type::inet || arg_type == Type::timestamp ||
        arg_type == Type::mac_address)
      arg_type = Type::string; // Symbols should be printed as strings
    if (arg_type == Type::pointer)
      arg_type = Type::integer; // Casts (pointers) can be printed as integers
    int offset = 1;

    // skip over format widths during verification
    if (token_iter->str()[offset] == '-')
      offset++;
    while ((token_iter->str()[offset] >= '0' && token_iter->str()[offset] <= '9') ||
           token_iter->str()[offset] == '.')
      offset++;

    const std::string token = token_iter->str().substr(offset);
    const auto token_type_iter = printf_format_types.find(token);
    if (token_type_iter == printf_format_types.end())
    {
      message << "printf: Unknown format string token: %" << token << std::endl;
      return message.str();
    }
    const Type &token_type = token_type_iter->second;

    if (arg_type != token_type)
    {
      message << "printf: %" << token << " specifier expects a value of type "
              << token_type << " (" << arg_type << " supplied)" << std::endl;
      return message.str();
    }
  }
  return "";
}

int PrintableString::print(char *buf, size_t size, const char *fmt)
{
  return snprintf(buf, size, fmt, value_.c_str());
}

int PrintableCString::print(char *buf, size_t size, const char *fmt)
{
  return snprintf(buf, size, fmt, value_);
}

int PrintableInt::print(char *buf, size_t size, const char *fmt)
{
  return snprintf(buf, size, fmt, value_);
}

int PrintableSInt::print(char *buf, size_t size, const char *fmt)
{
  return snprintf(buf, size, fmt, value_);
}
} // namespace bpftrace
