CXX ?= clang++
CXXFLAGS ?= -std=c++20 -pthread -I include -I /opt/homebrew/include
GRPC_CFLAGS := $(shell pkg-config --cflags grpc++ 2>/dev/null)
GRPC_LIBS := $(shell pkg-config --libs grpc++ 2>/dev/null)

TEST_SRC := test/holons_test.cpp
TEST_BIN := test_runner

.PHONY: test clean

# This Makefile targets POSIX toolchains. On Windows, use CMake/MSVC.
ifeq ($(OS),Windows_NT)
$(warning Use CMake (or MSVC directly) on Windows; this Makefile is POSIX-oriented.)
endif

test: $(TEST_BIN)
	./$(TEST_BIN)

$(TEST_BIN): $(TEST_SRC) include/holons/holons.hpp
	$(CXX) $(CXXFLAGS) $(GRPC_CFLAGS) $(TEST_SRC) -o $(TEST_BIN) $(GRPC_LIBS)

clean:
	rm -f $(TEST_BIN)
