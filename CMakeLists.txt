cmake_minimum_required(VERSION 3.14)
project(cpp-holons LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(test_runner test/holons_test.cpp)
target_include_directories(test_runner PRIVATE include)
target_include_directories(test_runner PRIVATE /opt/homebrew/include /usr/local/include)

if (WIN32)
  target_link_libraries(test_runner PRIVATE ws2_32)
endif()
