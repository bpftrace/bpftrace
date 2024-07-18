#include <thread>
#include <vector>


extern "C" {
void accept_positive(int x) {
}

void accept_mixed(int x) {
}
}

int main() {
  // TODO use jthread
  constexpr int num_threads = 100;
  std::vector<std::thread> threads;
  threads.reserve(num_threads);

  for (int i=0; i<num_threads; i++) {
    threads.emplace_back(accept_positive, i+1);
  }

  for (auto &thread : threads) {
    thread.join();
  }

  return 0;
}
