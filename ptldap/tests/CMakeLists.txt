cmake_minimum_required(VERSION 3.12)
project(ptldap_tests)

set(CMAKE_CXX_STANDARD 17)

include_directories(../)

file(GLOB LIB_SRC_FILES "ber.cpp")
set_property(SOURCE ${LIB_SRC_FILES} PROPERTY COMPILE_FLAGS -std=c++17)

add_executable(ber_tests
    test_main.cpp
    ${LIB_SRC_FILES}
)

#add_executable(ptldap_tests
#        test_main.cpp
#        all_tests.cpp
#)
