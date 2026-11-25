#!/usr/bin/env bash
# runs the suite under valgrind, or in a container if valgrind can't start on this machine
# container usage: VALGRIND_IMAGE=<image with g++ and valgrind> tests/valgrind.sh
src=$(cd "$(dirname "$0")/.." && pwd)

if ( ulimit -c 0; valgrind -q --error-exitcode=9 /bin/true ) >/dev/null 2>&1; then
    exec "$src/tests/run.sh" valgrind
fi
if [ -z "${VALGRIND_IMAGE:-}" ]; then
    echo "valgrind can't run here. Set VALGRIND_IMAGE to an image that has g++ and valgrind."
    exit 2
fi
exec docker run --rm --network none -v "$src":/src:ro "$VALGRIND_IMAGE" bash /src/tests/run.sh valgrind
