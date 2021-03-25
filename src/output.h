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
  // Write non-map value to output
  // Ideally, the implementation should use value_to_str to convert a value into
  // a string, format it properly, and print it to out_.
  virtual void value(BPFtrace &bpftrace,
                     const SizedType &ty,
                     std::vector<uint8_t> &value) const = 0;

  virtual void message(MessageType type, const std::string& msg, bool nl = true) const = 0;
  virtual void lost_events(uint64_t lost) const = 0;
  virtual void attached_probes(uint64_t num_probes) const = 0;

protected:
  std::ostream &out_;
  std::ostream &err_;
  void hist_prepare(const std::vector<uint64_t> &values, int &min_index, int &max_index, int &max_value) const;
  void lhist_prepare(const std::vector<uint64_t> &values, int min, int max, int step, int &max_index, int &max_value, int &buckets, int &start_value, int &end_value) const;

  // Convert non-map value into string
  // This method should properly handle all non-map value types.
  // Aggregate types (array, struct, tuple) are formatted using output-specific
  // methods.
  virtual std::string value_to_str(BPFtrace &bpftrace,
                                   const SizedType &type,
                                   std::vector<uint8_t> &value,
                                   bool is_per_cpu = false,
                                   uint32_t div = 1) const;
  // Convert an array to string
  // Default behaviour: [elem1, elem2, ...]
  virtual std::string array_to_str(const std::vector<std::string> &elems) const;
  // Convert a struct to string
  // Default behaviour: { elem1, elem2, ... }
  // elems are expected to be properly formatted
  virtual std::string struct_to_str(
      const std::vector<std::string> &elems) const;
  // Convert struct field (given by its name and value) into string
  virtual std::string field_to_str(const std::string &name,
                                   const std::string &value) const = 0;
  // Convert tuple to string
  virtual std::string tuple_to_str(
      const std::vector<std::string> &elems) const = 0;
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
                     std::vector<uint8_t> &value) const override;

  void message(MessageType type, const std::string& msg, bool nl = true) const override;
  void lost_events(uint64_t lost) const override;
  void attached_probes(uint64_t num_probes) const override;

private:
  static std::string hist_index_label(int power);
  static std::string lhist_index_label(int number);
  void hist(const std::vector<uint64_t> &values, uint32_t div) const;
  void lhist(const std::vector<uint64_t> &values, int min, int max, int step) const;

protected:
  std::string field_to_str(const std::string &name,
                           const std::string &value) const override;
  std::string tuple_to_str(
      const std::vector<std::string> &elems) const override;
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
                     std::vector<uint8_t> &value) const override;

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

protected:
  std::string value_to_str(BPFtrace &bpftrace,
                           const SizedType &type,
                           std::vector<uint8_t> &value,
                           bool is_per_cpu,
                           uint32_t div) const override;
  std::string field_to_str(const std::string &name,
                           const std::string &value) const override;
  std::string tuple_to_str(
      const std::vector<std::string> &elems) const override;
};

} // namespace bpftrace
