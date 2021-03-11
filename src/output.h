#pragma once

#include <iomanip>
#include <iostream>
#include <map>
#include <vector>

#include "imap.h"

namespace bpftrace {

enum class MessageType
{
  // don't forget to update std::ostream& operator<<(std::ostream& out,
  // MessageType type) in output.cpp
  map,
  value,
  hist,
  stats,
  printf,
  time,
  cat,
  join,
  syscall,
  attached_probes,
  lost_events
};

std::ostream& operator<<(std::ostream& out, MessageType type);

class Output
{
public:
  explicit Output(std::ostream& out = std::cout, std::ostream& err = std::cerr) : out_(out),err_(err) { }
  Output(const Output &) = delete;
  Output& operator=(const Output &) = delete;
  virtual ~Output() = default;

  virtual std::ostream& outputstream() const { return out_; };

  virtual void map(BPFtrace &bpftrace, IMap &map, uint32_t top, uint32_t div,
                   const std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>> &values_by_key) const = 0;
  virtual void map_hist(BPFtrace &bpftrace, IMap &map, uint32_t top, uint32_t div,
                        const std::map<std::vector<uint8_t>, std::vector<uint64_t>> &values_by_key,
                        const std::vector<std::pair<std::vector<uint8_t>, uint64_t>> &total_counts_by_key) const = 0;
  virtual void map_stats(
      BPFtrace &bpftrace,
      IMap &map,
      uint32_t top,
      uint32_t div,
      const std::map<std::vector<uint8_t>, std::vector<int64_t>> &values_by_key,
      const std::vector<std::pair<std::vector<uint8_t>, int64_t>>
          &total_counts_by_key) const = 0;
  virtual void value(BPFtrace &bpftrace,
                     const SizedType &ty,
                     const std::vector<uint8_t> &value) const = 0;

  virtual std::string struct_field_def_to_str(
      const std::string &field) const = 0;

  virtual void message(MessageType type, const std::string& msg, bool nl = true) const = 0;
  virtual void lost_events(uint64_t lost) const = 0;
  virtual void attached_probes(uint64_t num_probes) const = 0;

protected:
  std::ostream &out_;
  std::ostream &err_;
  void hist_prepare(const std::vector<uint64_t> &values, int &min_index, int &max_index, int &max_value) const;
  void lhist_prepare(const std::vector<uint64_t> &values, int min, int max, int step, int &max_index, int &max_value, int &buckets, int &start_value, int &end_value) const;
};

class TextOutput : public Output {
public:
  explicit TextOutput(std::ostream& out = std::cout, std::ostream& err = std::cerr) : Output(out, err) { }

  void map(BPFtrace &bpftrace, IMap &map, uint32_t top, uint32_t div,
           const std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>> &values_by_key) const override;
  void map_hist(BPFtrace &bpftrace, IMap &map, uint32_t top, uint32_t div,
                const std::map<std::vector<uint8_t>, std::vector<uint64_t>> &values_by_key,
                const std::vector<std::pair<std::vector<uint8_t>, uint64_t>> &total_counts_by_key) const override;
  void map_stats(
      BPFtrace &bpftrace,
      IMap &map,
      uint32_t top,
      uint32_t div,
      const std::map<std::vector<uint8_t>, std::vector<int64_t>> &values_by_key,
      const std::vector<std::pair<std::vector<uint8_t>, int64_t>>
          &total_counts_by_key) const override;
  virtual void value(BPFtrace &bpftrace,
                     const SizedType &ty,
                     const std::vector<uint8_t> &value) const override;
  std::string struct_field_def_to_str(const std::string &field) const override;

  void message(MessageType type, const std::string& msg, bool nl = true) const override;
  void lost_events(uint64_t lost) const override;
  void attached_probes(uint64_t num_probes) const override;

private:
  static std::string hist_index_label(int power);
  static std::string lhist_index_label(int number);
  void hist(const std::vector<uint64_t> &values, uint32_t div) const;
  void lhist(const std::vector<uint64_t> &values, int min, int max, int step) const;
  std::string tuple_to_str(BPFtrace &bpftrace,
                           const SizedType &ty,
                           const std::vector<uint8_t> &value) const;
};

class JsonOutput : public Output {
public:
  explicit JsonOutput(std::ostream& out = std::cout, std::ostream& err = std::cerr) : Output(out, err) { }

  void map(BPFtrace &bpftrace, IMap &map, uint32_t top, uint32_t div,
           const std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>> &values_by_key) const override;
  void map_hist(BPFtrace &bpftrace, IMap &map, uint32_t top, uint32_t div,
                const std::map<std::vector<uint8_t>, std::vector<uint64_t>> &values_by_key,
                const std::vector<std::pair<std::vector<uint8_t>, uint64_t>> &total_counts_by_key) const override;
  void map_stats(
      BPFtrace &bpftrace,
      IMap &map,
      uint32_t top,
      uint32_t div,
      const std::map<std::vector<uint8_t>, std::vector<int64_t>> &values_by_key,
      const std::vector<std::pair<std::vector<uint8_t>, int64_t>>
          &total_counts_by_key) const override;
  virtual void value(BPFtrace &bpftrace,
                     const SizedType &ty,
                     const std::vector<uint8_t> &value) const override;
  std::string struct_field_def_to_str(const std::string &field) const override;

  void message(MessageType type, const std::string& msg, bool nl = true) const override;
  void message(MessageType type, const std::string& field, uint64_t value) const;
  void lost_events(uint64_t lost) const override;
  void attached_probes(uint64_t num_probes) const override;

private:
  std::string json_escape(const std::string &str) const;

  void hist(const std::vector<uint64_t> &values, uint32_t div) const;
  void lhist(const std::vector<uint64_t> &values,
             int min,
             int max,
             int step) const;
  std::string tuple_to_str(BPFtrace &bpftrace,
                           const SizedType &ty,
                           const std::vector<uint8_t> &value) const;
};

} // namespace bpftrace
