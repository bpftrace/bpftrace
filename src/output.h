#pragma once

#include <iostream>
#include <iomanip>
#include <vector>
#include <map>

#include "imap.h"

namespace bpftrace {

class Output
{
public:
  explicit Output(std::ostream& o = std::cout) : out_(o) { }
  Output(const Output &) = delete;
  Output& operator=(const Output &) = delete;

  virtual std::ostream& outputstream() const { return out_; };

  virtual void map(BPFtrace &bpftrace, IMap &map, uint32_t top, uint32_t div,
                   const std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>> &values_by_key) const = 0;
  virtual void map_hist(BPFtrace &bpftrace, IMap &map, uint32_t top, uint32_t div,
                        const std::map<std::vector<uint8_t>, std::vector<uint64_t>> &values_by_key,
                        const std::vector<std::pair<std::vector<uint8_t>, uint64_t>> &total_counts_by_key) const = 0;
  virtual void map_stats(BPFtrace &bpftrace, IMap &map,
                         const std::map<std::vector<uint8_t>, std::vector<uint64_t>> &values_by_key,
                         const std::vector<std::pair<std::vector<uint8_t>, uint64_t>> &total_counts_by_key) const = 0;

  virtual void message(const std::string type, const std::string msg, bool nl = true) const = 0;
  virtual void lost_events(int lost) const = 0;

protected:
  std::ostream &out_;
  void hist_prepare(const std::vector<uint64_t> &values, int &min_index, int &max_index, int &max_value) const;
  void lhist_prepare(const std::vector<uint64_t> &values, int min, int max, int step, int &max_index, int &max_value, int &buckets, int &start_value, int &end_value) const;
};

class TextOutput : public Output {
public:
  explicit TextOutput(std::ostream& o = std::cout) : Output(o) { }

  void map(BPFtrace &bpftrace, IMap &map, uint32_t top, uint32_t div,
           const std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>> &values_by_key) const override;
  void map_hist(BPFtrace &bpftrace, IMap &map, uint32_t top, uint32_t div,
                const std::map<std::vector<uint8_t>, std::vector<uint64_t>> &values_by_key,
                const std::vector<std::pair<std::vector<uint8_t>, uint64_t>> &total_counts_by_key) const override;
  void map_stats(BPFtrace &bpftrace, IMap &map,
                 const std::map<std::vector<uint8_t>, std::vector<uint64_t>> &values_by_key,
                 const std::vector<std::pair<std::vector<uint8_t>, uint64_t>> &total_counts_by_key) const override;

  void message(const std::string type, const std::string msg, bool nl = true) const override;
  void lost_events(int lost) const override;

private:
  static std::string hist_index_label(int power);
  static std::string lhist_index_label(int number);
  void hist(const std::vector<uint64_t> &values, uint32_t div) const;
  void lhist(const std::vector<uint64_t> &values, int min, int max, int step) const;
};

class JsonOutput : public Output {
public:
  explicit JsonOutput(std::ostream& o = std::cout) : Output(o) { }

  void map(BPFtrace &bpftrace, IMap &map, uint32_t top, uint32_t div,
           const std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>> &values_by_key) const override;
  void map_hist(BPFtrace &bpftrace, IMap &map, uint32_t top, uint32_t div,
                const std::map<std::vector<uint8_t>, std::vector<uint64_t>> &values_by_key,
                const std::vector<std::pair<std::vector<uint8_t>, uint64_t>> &total_counts_by_key) const override;
  void map_stats(BPFtrace &bpftrace, IMap &map,
                 const std::map<std::vector<uint8_t>, std::vector<uint64_t>> &values_by_key,
                 const std::vector<std::pair<std::vector<uint8_t>, uint64_t>> &total_counts_by_key) const override;

  void message(const std::string type, const std::string msg, bool nl = true) const override;
  void lost_events(int lost) const override;

private:
  std::string json_escape(const std::string &str) const;

  void hist(const std::vector<uint64_t> &values, uint32_t div) const;
  void lhist(const std::vector<uint64_t> &values, int min, int max, int step) const;
};

} // namespace bpftrace
