set -e
cd /bpftrace
mkdir -p build-docker
cd build-docker
cmake -DCMAKE_BUILD_TYPE=Debug ../
make
