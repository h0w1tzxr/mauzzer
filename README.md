# Mauzzer

A tiny binary fuzzer and bug tracker in C++. It mutates packets, runs them through a deliberately buggy parser, and links each packet to the bugs it triggers.

```
g++ -std=c++11 *.cpp -o mauzzer && ./mauzzer
```

Type `21` to add the known bugs, `22` to fuzz, and `14` to see the results. Type `?` for the full menu.

```
tests/run.sh
tests/valgrind.sh
```
