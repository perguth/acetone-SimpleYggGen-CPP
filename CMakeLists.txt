cmake_minimum_required(VERSION 3.0)

project(sygcpp)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -static")

add_subdirectory(src/yggdrasil-0.4.x)
