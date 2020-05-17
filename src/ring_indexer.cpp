#include "ring_indexer.h"
#include <utility>

namespace bpftrace {

RingIndexer::RingIndexer(int maxEntries)
: maxEntries(maxEntries)
{
}

std::tuple<bool, int> RingIndexer::getFreeIndex() {
  const int proposedEndOfUsedEntries = (endOfUsedEntries+1) % maxEntries;
  if (proposedEndOfUsedEntries == startOfUsedEntries) {
    return std::make_tuple(false, -1);
  }
  endOfUsedEntries = proposedEndOfUsedEntries;
  return std::make_tuple(true, endOfUsedEntries);
}

void RingIndexer::freeIndex(int freed) {
  startOfUsedEntries = (freed+1) % maxEntries;
}

}