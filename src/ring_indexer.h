#pragma once

#include <memory>
#include <tuple>

namespace bpftrace {

class RingIndexer {
public:
    RingIndexer(int maxEntries);
    /**
     * @return <success, index>
     */
    std::tuple<bool, int> getFreeIndex();
    /**
     * Freeing entry n implies freeing all entries before n too.
     * RingIndexer should only be used in single-threaded event queues,
     * e.g. where processing a newer event means you either processed
     * older events or dropped them.
     */
    void freeIndex(int freed);
private:
    const int maxEntries;
    int startOfUsedEntries = 0;
    int endOfUsedEntries = 0;
};

}