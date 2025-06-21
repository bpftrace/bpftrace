#include <array>
#include <cassert>
#include <iomanip>
#include <optional>
#include <variant>

#include "progress.h"

namespace bpftrace {

namespace {

enum Color {
  Black = 0,
  Gray = 8,
  Red = 9,
  Green = 10,
  Yellow = 11,
  Blue = 12,
  Cyan = 13,
  Turquoise = 14,
  White = 15,
};

class SilentProgress : public ProgressImpl<SilentProgress> {
public:
  class Bounded : public BoundedProgress {
  public:
    Bounded([[maybe_unused]] SilentProgress *parent,
            [[maybe_unused]] const std::string &name) {};
    void add_goal([[maybe_unused]] size_t sz) override {};
    void add_progress([[maybe_unused]] size_t sz) override {};
  };
  class Unbounded : public UnboundedProgress {
  public:
    Unbounded([[maybe_unused]] SilentProgress *parent,
              [[maybe_unused]] const std::string &name) {};
    void tick() override {};
  };
};

class ConsoleProgress : public ProgressImpl<ConsoleProgress> {
public:
  class Bounded : public BoundedProgress {
  public:
    Bounded(ConsoleProgress *parent, const std::string &name);
    ~Bounded() override { parent_->out << std::endl; };
    void add_goal(size_t sz) override;
    void add_progress(size_t sz) override;

  private:
    ConsoleProgress *parent_;
    const std::string &name_;
    size_t total_ = 0;
    size_t done_ = 0;
  };
  class Unbounded : public UnboundedProgress {
  public:
    Unbounded(ConsoleProgress *parent, const std::string &name);
    ~Unbounded() override { parent_->out << std::endl; };
    void tick() override;
    void cycle_colors();

  private:
    ConsoleProgress *parent_;
    const std::string &name_;
    size_t done_ = 0;
    size_t wheel_idx_ = 0;
    std::optional<Color> fg_;
    std::optional<Color> bg_;
  };
  ConsoleProgress(std::ostream &out, bool color) : out(out), color(color) {};

  // These are usable by the instances.
  std::ostream &out;
  const bool color;
};

} // namespace

// The eight blocks from 1/8th to the full block.
static const std::array<std::string, 9> blocks = {
  " ", "▏", "▎", "▍", "▌", "▋", "▊", "▉", "█",
};

// Definitions for cycle colors.
static const std::array<Color, 2> wheel = {
  Black,
  Yellow,
};

// The `emit` function will force a standardized with for progress bars, in
// order for the output to look reasonable with multiple instances.
static const size_t WIDTH = 60;
static const size_t TEXT_WIDTH = 40;
static const size_t BAR_WIDTH = WIDTH - TEXT_WIDTH;

// Emit a (optionally colorized) progress bar to the given stream. The width
// provided by be at least 3, or an assertion will fail.
//
// Note that if true is returned, it means that a full cycle has been
// completed. This can be used by the caller in any suitable way.
static bool emit(std::ostream &out,
                 const std::string &prefix,
                 std::variant<double, size_t> progress,
                 std::optional<Color> fg = std::nullopt,
                 std::optional<Color> bg = std::nullopt)
{
  bool complete = false;
  out << std::setw(TEXT_WIDTH) << std::left << ("\r" + prefix + "...");

  // Empty our prefix and enable colors.
  out << "[";
  if (fg) {
    out << "\e[38;5;" << static_cast<int>(*fg) << "m";
  }
  if (bg) {
    out << "\e[48;5;" << static_cast<int>(*bg) << "m";
  }

  // Compute our different spans.
  auto bar_width = static_cast<double>(BAR_WIDTH - 2);
  if (std::holds_alternative<double>(progress)) {
    auto percentage = std::get<double>(progress);
    if (percentage > 0.999) {
      // Emit a full bar.
      for (size_t i = 0; i < BAR_WIDTH - 2; i++) {
        out << blocks[blocks.size() - 1];
      }
      complete = true;
    } else {
      // Compute the partial bar required.
      auto full = std::min(static_cast<size_t>(bar_width * percentage), BAR_WIDTH - 3);
      auto empty = (BAR_WIDTH - 3) - full;

      // Emit the full blocks.
      for (size_t i = 0; i < full; i++) {
        out << blocks[blocks.size() - 1];
      }

      // Emit the partial block; this is always included and may actually be full.
      out << blocks[static_cast<size_t>(bar_width * blocks.size() * percentage) % blocks.size()];

      // Empty the empty blocks.
      for (size_t i = 0; i < empty; i++) {
        out << ' ';
      }
    }
  } else {
    // We simply treat every block as an incremental meter. We don't apply the
    // `blocks.size()` multiplier here, since we generally want this to move a
    // bit slower.
    auto idx = std::get<size_t>(progress) % blocks.size();
    for (size_t i = 0; i < BAR_WIDTH - 2; i++) {
      out << blocks[idx];
    }
    if (idx == blocks.size() - 1) {
      complete = true;
    }
  }

  // Reset all colors.
  if (fg || bg) {
    out << "\e[0m";
  }
  out << "]";
  out.flush();
  return complete;
}

ConsoleProgress::Bounded::Bounded(ConsoleProgress *parent,
                                  const std::string &name)
    : parent_(parent), name_(name)
{
}

void ConsoleProgress::Bounded::add_goal(size_t sz)
{
  total_ += sz;
  emit(parent_->out,
       name_,
       static_cast<double>(done_) / static_cast<double>(total_));
}

void ConsoleProgress::Bounded::add_progress(size_t sz)
{
  done_ += sz;
  if (total_ != 0) {
    // The bounded progress currently does not use colors.
    emit(parent_->out,
         name_,
         static_cast<double>(done_) / static_cast<double>(total_));
  }
}

ConsoleProgress::Unbounded::Unbounded(ConsoleProgress *parent,
                                      const std::string &name)
    : parent_(parent), name_(name)
{
  if (parent_->color) {
    cycle_colors();
  }
}

void ConsoleProgress::Unbounded::cycle_colors()
{
  if (fg_) {
    bg_.emplace(*fg_);
  }
  fg_.emplace(wheel[wheel_idx_]);
  wheel_idx_ = (wheel_idx_ + 1) % wheel.size();
}

void ConsoleProgress::Unbounded::tick()
{
  bool complete = emit(parent_->out, name_, done_, fg_, bg_);
  done_++;
  if (complete && parent_->color) {
    cycle_colors();
  }
}

std::unique_ptr<Progress> CreateSilentProgress()
{
  return std::make_unique<SilentProgress>();
}

std::unique_ptr<Progress> CreateConsoleProgress(std::ostream &out, bool color)
{
  return std::make_unique<ConsoleProgress>(out, color);
}

} // namespace bpftrace
