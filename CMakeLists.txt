cmake_minimum_required(VERSION 3.12)
project(tuxID)

set(CMAKE_CXX_STANDARD 17)

add_executable(tuxID hardwareID.hpp obfuscation.hpp main.cpp)
target_link_libraries(tuxID PUBLIC udev )
