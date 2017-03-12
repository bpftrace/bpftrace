set -e
DIR="$1/build-docker"
mkdir -p "$DIR"
cd "$DIR"
cmake -DCMAKE_BUILD_TYPE=Debug ../
make
