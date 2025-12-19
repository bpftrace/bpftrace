#include <algorithm>
#include <cassert>
#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <vector>

//
// Table entry format:
//     own key
//     left child ptr or leaf marker
//     own value
//     right subtree
//     left subtree
//
//  key is relative to parent key
//  ptrs are offsets from end of current entry
//  a pointer marks whether it points to a leaf or not
//
//  leaf node format:
//     own key
//     left key
//     left value
//     own value
//     right key
//     right value
//
//  The tree can have one leaf in the tree that is not pointed to by a ptr,
//  thus not explicitly marked as leaf. If present, this is always the rightmost
//  leaf in the tree. All other leaves are full.
//
//  incomplete leaf format;
//     own key       (0 for empty leaf)
//     leaf marker   (can be distinguished from ptrs)
//     left key      (0 if no left entry)
//     left value
//     own value
//     right key     (0 if no right entry)
//     right value
//
// encoding:
// ptrs: we limit the table size to 2MB, so 21 bits
//   00-CF: encode as 1 byte
//   D0-D8: first byte with 3 lower bits of value, followed by 2 bytes
//          (little-endian)
// leaf ptrs:
//   D8-DF: first byte with 3 lower bits of value, followed by 2 bytes
//          (little-endian)
//   E0-FF: ptr as 1 byte
// values:
//   00-F6: encode as 1 byte
//   F8-FF: first byte with 3 lower bits of value, followed by 1 byte
//   F7   : followed by 3 bytes u64
// RelKey:
//   00-DE: 1 byte, val + 111
//   DF   : followed by 8 bytes i64 (little-endian)
//   E0-FF: lower 5 bits, followed by 1 byte (little-endian)
//
// a ptr with value 0 is used to mark a leaf that is pointed to by a
// non-leaf ptr
//   This can happen only for the last right child
//
// Maximum encodable table size is 256k
//

struct PtrTooLarge : std::runtime_error {
  PtrTooLarge() : std::runtime_error("table pointer too large")
  {
  }
};

static std::vector<uint8_t> enc_rel_key(int64_t rel_key)
{
  auto ukey = static_cast<uint64_t>(rel_key);

  if (rel_key >= -111 && rel_key <= 111) {
    return { static_cast<uint8_t>(rel_key + 111) };
  } else if (rel_key >= -0x1000 && rel_key < 0x1000) {
    return { static_cast<uint8_t>(0xe0 | ((ukey >> 8) & 0x1f)),
             static_cast<uint8_t>(ukey & 0xff) };
  } else {
    return { 0xdf,
             static_cast<uint8_t>(ukey & 0xff),
             static_cast<uint8_t>((ukey >> 8) & 0xff),
             static_cast<uint8_t>((ukey >> 16) & 0xff),
             static_cast<uint8_t>((ukey >> 24) & 0xff),
             static_cast<uint8_t>((ukey >> 32) & 0xff),
             static_cast<uint8_t>((ukey >> 40) & 0xff),
             static_cast<uint8_t>((ukey >> 48) & 0xff),
             static_cast<uint8_t>((ukey >> 56) & 0xff) };
  }
}

static std::vector<uint8_t> enc_rel_ptr(uint64_t rel_ptr)
{
  if (rel_ptr <= 0xcf) {
    return { static_cast<uint8_t>(rel_ptr) };
  } else if (rel_ptr <= 0x3ffff) {
    return { static_cast<uint8_t>(0xd0 | ((rel_ptr >> 16) & 0x07)),
             static_cast<uint8_t>(rel_ptr & 0xff),
             static_cast<uint8_t>(rel_ptr >> 8) };
  } else {
    throw PtrTooLarge();
  }
}

static std::vector<uint8_t> enc_rel_leaf_ptr(uint64_t rel_ptr)
{
  if (rel_ptr <= 0x1f) {
    return { static_cast<uint8_t>(0xe0 | rel_ptr) };
  } else if (rel_ptr <= 0x3ffff) {
    return { static_cast<uint8_t>(0xd8 | ((rel_ptr >> 16) & 0x07)),
             static_cast<uint8_t>(rel_ptr & 0xff),
             static_cast<uint8_t>(rel_ptr >> 8) };
  } else {
    throw PtrTooLarge();
  }
}

static std::vector<uint8_t> enc_leaf_marker()
{
  return { 0x00 };
}

static std::vector<uint8_t> enc_value(uint64_t val)
{
  if (val <= 0xf6) {
    return { static_cast<uint8_t>(val) };
  } else if (val <= 0x3ff) {
    return { static_cast<uint8_t>(0xf8 | ((val >> 8) & 0x07)),
             static_cast<uint8_t>(val & 0xff) };
  } else if (val <= 0xffffff) {
    return {
      0xf7,
      static_cast<uint8_t>((val >> 16) & 0xff),
      static_cast<uint8_t>((val >> 8) & 0xff),
      static_cast<uint8_t>(val & 0xff),
    };
  } else {
    throw std::runtime_error("table value too large");
  }
}

static int push(std::vector<uint8_t>& buf, const std::vector<uint8_t>& data)
{
  // insert in reverse order
  buf.insert(buf.end(), data.rbegin(), data.rend());

  return data.size();
}

struct BuildStats {
  uint64_t bytes_in_keys = 0;
  uint64_t bytes_in_values = 0;
};

static uint64_t build_recurse(
    BuildStats& stats,
    std::vector<uint8_t>& buf,
    const std::vector<std::pair<uint64_t, uint64_t>>& entries,
    size_t start,
    size_t end,
    uint64_t parent_key,
    bool unmarked_leaf)
{
  int n;

  // observations:
  //  - due to the rules the split point is chosen, the left subtree will
  //    always be full, so either a node has 2 full leaves or is a leaf itself
  //  - if the left node is a leaf, the right also is
  //  - if the left node is not a leaf, the right may be a leaf. As there is
  //    no right pointer, we can't encode the leafness into the pointer, so
  //    we encode it into the key
  //  - the right node always immediately follows its parent, so we don't need
  //    a right pointer
  //  - to be able to calculate the forward pointers, we have to build from back
  //    to front
  auto len = end - start;

  /*
   * leaf node
   */
  if (len <= 3) {
    // <key> [<leaf marker>] <left key> <left value> <own value> <right key>
    //  <right value>
    // a key of 0 means the entry is not valid
    // emitted back to front

    uint64_t own_key;
    if (len == 0)
      own_key = parent_key; // this entry is a dummy entry, choose it so it is 0
    else if (len == 1)
      own_key = entries[start].first;
    else
      own_key = entries[start + 1].first;

    // right key/value
    if (len == 3) {
      n = push(buf, enc_value(entries[start + 2].second));
      stats.bytes_in_values += n;
      n = push(buf, enc_rel_key(entries[start + 2].first - own_key));
      stats.bytes_in_keys += n;
    } else {
      // dummy entry
      push(buf, enc_value(0));
      push(buf, enc_rel_key(0));
    }

    // own value
    if (len > 0) {
      auto own_value = entries[start + (len >= 2 ? 1 : 0)].second;
      n = push(buf, enc_value(own_value));
      stats.bytes_in_values += n;
    } else {
      // dummy entry
      push(buf, enc_value(0));
    }

    // left key/value
    if (len >= 2) {
      n = push(buf, enc_value(entries[start].second));
      stats.bytes_in_values += n;
      n = push(buf, enc_rel_key(entries[start].first - own_key));
      stats.bytes_in_keys += n;
    } else {
      // dummy entry
      push(buf, enc_value(0));
      push(buf, enc_rel_key(0));
    }

    // leaf marker
    if (unmarked_leaf)
      push(buf, enc_leaf_marker());

    // own key
    if (len >= 1) {
      n = push(buf, enc_rel_key(own_key - parent_key));
      stats.bytes_in_keys += n;
    } else {
      // dummy entry
      push(buf, enc_rel_key(0));
    }

    return buf.size();
  }

  /*
   * intermediate node
   */

  // split point: find largest number that creates a tree with no empty pointers
  size_t split = 3;
  while ((2 * split) + 1 + 1 <= len) {
    split = (2 * split) + 1;
  }
  split += start;

  auto own_key = entries[split].first;
  auto own_value = entries[split].second;

  auto left_len = split - start;
  auto right_len = end - (split + 1);
  assert(left_len >= 3);
  auto left_is_leaf = left_len == 3;
  auto right_is_leaf = right_len <= 3;
  auto right_unmarked_leaf = right_is_leaf && !left_is_leaf;

  // <own key> <left ptr> <own value> <right subtree> <left subtree>
  // built from back to front
  // left subtree
  auto left_ptr = build_recurse(
      stats, buf, entries, start, split, own_key, false);
  // right subtree
  build_recurse(
      stats, buf, entries, split + 1, end, own_key, right_unmarked_leaf);

  // own value
  n = push(buf, enc_value(own_value));
  stats.bytes_in_values += n;

  // left ptr
  if (left_is_leaf) {
    n = push(buf, enc_rel_leaf_ptr(buf.size() - left_ptr));
  } else {
    n = push(buf, enc_rel_ptr(buf.size() - left_ptr));
  }

  // own key
  n = push(buf, enc_rel_key(own_key - parent_key));
  stats.bytes_in_keys += n;

  return buf.size();
}

std::vector<uint8_t> build_table(
    const std::vector<std::pair<uint64_t, uint64_t>>& entries,
    size_t start,
    size_t max_size,
    size_t& out_entries)
{
  size_t left = 0;
  size_t right = entries.size() - start;
  size_t n = std::min(static_cast<size_t>(max_size / 2.6),
                      entries.size() - start);

  std::vector<uint8_t> result_buf;
  size_t result_entries = 0;
  // find a number of entries that fills the available space well
  while (left < right) {
    BuildStats stats = {};
    std::vector<uint8_t> buf;

    try {
      build_recurse(stats, buf, entries, start, start + n, 0, false);
    } catch (const PtrTooLarge&) {
      // too large, try fewer entries
    }

    auto diff = static_cast<signed long>(buf.size()) -
                static_cast<signed long>(max_size);
    auto adj = std::max(static_cast<size_t>(labs(diff) / 2.6), 1UL);
    if (buf.size() > max_size) {
      right = n - 1;
      n = std::max(n - adj, left);
    } else {
      std::swap(result_buf, buf);
      result_entries = n;
      left = n;
      n = std::min(n + adj, right);
      if (labs(diff) < 100.0)
        break;
    }
  }

  std::ranges::reverse(result_buf);

  out_entries = result_entries;
  if (result_entries > 0)
    return result_buf;
  else
    return {};
}
