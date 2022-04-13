#include "format_string.h"
#include "log.h"
#include "struct.h"

namespace bpftrace {

const int FMT_BUF_SZ = 512;

std::string validate_format_string(const std::string &fmt,
                                   std::vector<Field> args)
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
  for (int i = 0; i < num_args; i++, token_iter++)
  {
    Type arg_type = args.at(i).type.type;
    if (arg_type == Type::ksym || arg_type == Type::usym ||
        arg_type == Type::probe || arg_type == Type::username ||
        arg_type == Type::kstack || arg_type == Type::ustack ||
        arg_type == Type::inet || arg_type == Type::timestamp ||
        arg_type == Type::mac_address || arg_type == Type::cgroup_path)
      arg_type = Type::string; // Symbols should be printed as strings
    if (arg_type == Type::pointer)
      arg_type = Type::integer; // Casts (pointers) can be printed as integers
    int offset = 1;

    // skip over format widths during verification
    if (token_iter->str()[offset] == '-')
      offset++;
    while ((token_iter->str()[offset] >= '0' &&
            token_iter->str()[offset] <= '9') ||
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

void FormatString::split()
{
  auto tokens_begin = std::sregex_iterator(fmt_.begin(),
                                           fmt_.end(),
                                           format_specifier_re);
  auto tokens_end = std::sregex_iterator();

  size_t last_pos = 0;
  for (std::regex_iterator i = tokens_begin; i != tokens_end; i++)
  {
    int end = i->position() + i->length();
    parts_.push_back(fmt_.substr(last_pos, end - last_pos));
    last_pos = end;
  }

  if (last_pos != fmt_.length())
  {
    parts_.push_back(fmt_.substr(last_pos));
  }
}

void FormatString::format(std::ostream &out,
                          std::vector<std::unique_ptr<IPrintable>> &args)
{
  if (parts_.size() < 1)
  {
    split();
  }
  auto buffer = std::vector<char>(FMT_BUF_SZ);
  auto check_snprintf_ret = [](int r) {
    if (r < 0)
    {
      LOG(FATAL) << "format() error occurred: " << std::strerror(errno);
    }
  };

  size_t i = 0;
  for (; i < args.size(); i++)
  {
    for (int try_ = 0; try_ < 2; try_++)
    {
      // find format specified in the string
      auto last_percent_sign = parts_[i].find_last_of('%');
      std::string fmt_string = last_percent_sign != std::string::npos
                                   ? parts_[i].substr(last_percent_sign)
                                   : "";
      std::string printf_fmt;
      if (fmt_string == "%r" || fmt_string == "%rx")
      {
        if (fmt_string == "%rx")
        {
          auto printable_buffer = dynamic_cast<PrintableBuffer *>(&*args.at(i));
          // this is checked by semantic analyzer
          assert(printable_buffer);
          printable_buffer->keep_ascii(false);
        }
        // replace nonstandard format specifier with %s
        printf_fmt = std::regex_replace(parts_[i], std::regex("%rx?"), "%s");
      }
      else
      {
        printf_fmt = parts_[i];
      }
      int r = args.at(i)->print(buffer.data(),
                                buffer.capacity(),
                                printf_fmt.c_str());
      check_snprintf_ret(r);
      if (static_cast<size_t>(r) < buffer.capacity())
        // string fits into buffer, we are done
        break;
      else
        // the buffer is not big enough to hold the string, resize it
        // and try again
        buffer.resize(r + 1);
    }

    out << buffer.data();
  }
  if (i < parts_.size())
  {
    out << parts_[i];
  }
}

std::string FormatString::format_str(
    std::vector<std::unique_ptr<IPrintable>> &args)
{
  std::stringstream buf;
  format(buf, args);
  return buf.str();
}

} // namespace bpftrace
