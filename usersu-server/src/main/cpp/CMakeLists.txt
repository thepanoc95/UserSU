cmake_minimum_required(VERSION 3.22.1)
project("usersu_kernel")

add_library(usersu_kernel SHARED
    dev/github/thepanoc95/usersu/backend/UsermodeKernel.cpp
)

target_include_directories(usersu_kernel PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_compile_options(usersu_kernel PRIVATE
    -Wall -Werror -Wno-unused-parameter
    -fvisibility=hidden
    -fPIE
)

target_compile_definitions(usersu_kernel PRIVATE
    _GNU_SOURCE
    ANDROID
)

find_library(log-lib log)
find_library(android-lib android)

target_link_libraries(usersu_kernel
    ${log-lib}
    ${android-lib}
    jnigraphics
    dl
    z
)
