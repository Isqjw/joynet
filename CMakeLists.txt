cmake_minimum_required(VERSION 3.3)

project(Joynet)

SET(CMAKE_BUILD_TYPE "Debug")
SET(CMAKE_CXX_FLAGS_DEBUG "$ENV{CXXFLAGS} -O0 -Wall -g2 -ggdb")
SET(CMAKE_CXX_FLAGS_RELEASE "$ENV{CXXFLAGS} -O3 -Wall")

#message(STATUS "source dir: ${CMAKE_SOURCE_DIR}")
#message(STATUS "complie flags: ${STRICT_COMPILE_FLAGS}")

add_executable(client joyclient.c joynet.c joyblock.c)
add_executable(server joyserver.c joynet.c joyblock.c)
