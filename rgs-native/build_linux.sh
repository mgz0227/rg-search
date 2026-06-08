#!/usr/bin/env sh
set -eu
CXX=${CXX:-g++}
$CXX -std=c++20 -O3 -DNDEBUG -pthread src/rgs.cpp -o rgs
./rgs --self-test
