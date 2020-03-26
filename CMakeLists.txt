cmake_minimum_required(VERSION 3.3)

project(Joynet)

set(COMMON_COMPILE_FLAGS "-g -Wall -Wno-long-long -Werror -D_NEW_LIC -D_GNU_SOURCE -D_REENTRANT -fPIC -D__STDC_FORMAT_MACROS -DSVR_ONLY")
set(STRICT_COMPILE_FLAGS "${COMMON_COMPILE_FLAGS} -DDEV_BUILD")
set(CMAKE_CXX_FLAGS ${STRICT_COMPILE_FLAGS})

add_executable(joyclient joyclient.c joynet.c)
add_executable(joyserver joyserver.c joynet.c)
