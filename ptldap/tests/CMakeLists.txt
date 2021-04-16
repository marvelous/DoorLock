cmake_minimum_required(VERSION 3.12)
project(ptldap_tests)

set(CMAKE_CXX_STANDARD 17)

include_directories(../)

add_executable(ptldap_tests
        test_main.cpp
        all_tests.cpp
)
