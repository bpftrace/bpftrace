set -e
mkdir -p "$1"
cd "$1"
cmake -DCMAKE_BUILD_TYPE="$2" ../
shift 2
make "$@"
