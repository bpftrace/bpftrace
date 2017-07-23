#include <regex>

#include "printf.h"

namespace bpftrace {

std::string verify_format_string(const std::string &fmt, std::vector<SizedType> args)
{
  std::stringstream message;
  std::regex re("%[a-zA-Z]");

  auto tokens_begin = std::sregex_iterator(fmt.begin(), fmt.end(), re);
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
    Type arg_type = args.at(i).type;
    char token = token_iter->str()[1];

    Type token_type;
    switch (token)
    {
      case 'd':
      case 'u':
      case 'x':
      case 'X':
        token_type = Type::integer;
        break;
      case 's':
        token_type = Type::string;
        break;
      default:
        message << "printf: Unknown format string token: %" << token << std::endl;
        return message.str();
    }

    if (arg_type != token_type)
    {
      message << "printf: %" << token << " specifier expects a value of type "
              << token_type << " (" << arg_type << " supplied)" << std::endl;
      return message.str();
    }
  }
  return "";
}

} // namespace bpftrace
