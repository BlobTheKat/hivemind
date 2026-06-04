cd tests 2>/dev/null
set -e
# clang -g -Og -fsanitize=address -fsanitize=undefined -I.. $1.c -o test.out
clang -O3 -I../include $1.c -o test.out
set +e
./test.out
rm test.out