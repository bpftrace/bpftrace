#pragma once

#include <chrono>
#include <cstdint>
#include <iostream>
#include <string>
#include <variant>
#include <vector>

#include "required_resources.h" // For RuntimeErrorInfo.

namespace bpftrace::output {

// Primitive is a basic value.
//
// This covers basic atoms, arrays, structures, etc. Primitives are guaranteed
// to be orderable and comparable.
//
// It does not cover any advanced maps.
struct Primitive {
  struct Array {
    std::vector<Primitive> values;
    std::partial_ordering operator<=>(const Array& other) const;
    bool operator==(const Array& other) const;
  };
  struct Buffer {
    std::vector<char> data;
    std::strong_ordering operator<=>(const Buffer& other) const = default;
    bool operator==(const Buffer& other) const = default;
  };
  struct Tuple {
    std::vector<std::pair<std::string, Primitive>> fields;
    bool is_named = false;
    std::partial_ordering operator<=>(const Tuple& other) const;
    bool operator==(const Tuple& other) const;
  };
  struct Record {
    std::vector<std::pair<std::string, Primitive>> fields;
    std::partial_ordering operator<=>(const Record& other) const;
    bool operator==(const Record& other) const;
  };
  struct Symbolic {
    Symbolic(std::string s, uint64_t n) : symbol(std::move(s)), numeric(n) {};
    std::string symbol;
    uint64_t numeric;
    auto operator<=>(const Symbolic& other) const = default;
    bool operator==(const Symbolic& other) const = default;
  };
  using Timestamp = std::chrono::time_point<std::chrono::system_clock>;
  using Duration = std::chrono::duration<uint64_t, std::nano>;
  using Variant = std::variant<std::monostate,
                               bool,
                               int64_t,
                               uint64_t,
                               double,
                               std::string,
                               Array,
                               Buffer,
                               Tuple,
                               Record,
                               Symbolic,
                               Timestamp,
                               Duration>;

  template <typename T>
  Primitive(T&& t)
    requires std::constructible_from<Variant, T>
      : variant(std::forward<T>(t)){};

  auto operator<=>(const Primitive& other) const = default;
  bool operator==(const Primitive& other) const = default;

  Variant variant;
};

// Primitives have a default representation.
std::ostream& operator<<(std::ostream& out, const Primitive& p);

// Value is an arbitrary value.
//
// This is a primitive, or a high-level aggregation over values. It is not
// guaranteed to be orderable or comparable.
struct Value {
  // Histogram is a specific type of value, which contains a sequence
  // of labels that represent the end interval for buckets, and a sequence of
  // counts. All the labels are typically numbers, strings or `Symbolic`.
  //
  // The labels field represents the upper bounds for each of the buckets,
  // and if counts is larger than labels then the top bucket has no upper bound.
  //
  // If there is a lower-bound for the first bucket, it is specified within the
  // lower_bound field.
  struct Histogram {
    std::optional<Primitive> lower_bound;
    std::vector<Primitive> labels;
    std::vector<uint64_t> counts;
  };

  // OrderedMap defines a map that can be ordered externally, and therefore
  // is not necessarily bound to be ordered by key.
  struct OrderedMap {
    std::vector<std::pair<Primitive, Value>> values;
  };

  // Stats is just an arbitrary classifier for another value. It changes
  // only some of the encoding used by some outputs.
  struct Stats {
    Stats(OrderedMap&& m) : value(std::move(m)) {};
    Stats(Primitive&& p) : value(std::move(p)) {};
    std::variant<OrderedMap, Primitive> value;
  };

  // TimeSeries is a sequence of values that are collected over time.
  struct TimeSeries {
    std::vector<std::pair<Primitive::Timestamp, Primitive>> values;
  };

  using Variant = std::variant<Primitive,
                               Histogram,
                               std::vector<Value>,
                               OrderedMap,
                               Stats,
                               TimeSeries>;

  template <typename T>
  Value(T&& t)
    requires std::constructible_from<Variant, T>
      : variant(std::forward<T>(t)){};

  Variant variant;
};

// Abstract class for output.
//
// This should be overriden by individual implementations.
class Output {
public:
  virtual ~Output() = default;

  // Print high-level maps, with special support for histogram-type maps,
  // and "stats" maps, where richer statistics are required. The exact
  // statistics or method for publishing the histograms is up to the engine.
  //
  // The "stats" boolean indicates whether this should be considered as "stats"
  // map or not, in order to preserve message types for JSON encoding.
  virtual void map(const std::string& name, const Value& value) = 0;

  // Print an arbitrary value.
  virtual void value(const Value& value) = 0;

  // Specialized messages during execution.
  virtual void printf(const std::string& str,
                      const SourceInfo& info,
                      PrintfSeverity severity) = 0;
  virtual void time(const std::string& time) = 0;
  virtual void cat(const std::string& cat) = 0;
  virtual void join(const std::string& join) = 0;
  virtual void syscall(const std::string& syscall) = 0;
  virtual void end() = 0;

  // General events.
  virtual void lost_events(uint64_t lost) = 0;
  virtual void attached_probes(uint64_t num_probes) = 0;
  virtual void runtime_error(int retcode, const RuntimeErrorInfo& info) = 0;

  // Testing hooks.
  virtual void test_result(const std::vector<std::string>& all_tests,
                           size_t index,
                           std::chrono::nanoseconds result,
                           const std::vector<bool>& passed,
                           std::string output) = 0;

  // Benchmark hooks.
  virtual void benchmark_result(const std::vector<std::string>& all_benches,
                                size_t index,
                                std::chrono::nanoseconds average,
                                size_t iters) = 0;
};

} // namespace bpftrace::output
