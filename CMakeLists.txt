cmake_minimum_required(VERSION 3.14)
project(proxy_server VERSION 1.0 LANGUAGES CXX)

# ---- C++17 required ---------------------------------------------------------
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# ---- Build type defaults -----------------------------------------------------
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

# ---- Compiler warnings -------------------------------------------------------
add_compile_options(
    -Wall
    -Wextra
    -Wpedantic
    -Wno-unused-parameter   # common in POSIX/OpenSSL callbacks
)

# ---- Find OpenSSL ------------------------------------------------------------
find_package(OpenSSL REQUIRED)

# ---- Source files ------------------------------------------------------------
set(SOURCES
    src/main.cpp
)

# ---- Executable --------------------------------------------------------------
add_executable(proxy_server ${SOURCES})

target_include_directories(proxy_server PRIVATE src)

target_link_libraries(proxy_server
    PRIVATE
        OpenSSL::SSL
        OpenSSL::Crypto
        Threads::Threads   # pthreads (needed for std::thread on Linux)
)

# Pull in pthreads via CMake's portable Threads module.
find_package(Threads REQUIRED)
target_link_libraries(proxy_server PRIVATE Threads::Threads)

# ---- Installation (optional) -------------------------------------------------
install(TARGETS proxy_server DESTINATION bin)

# ---- Print config summary at configure time ----------------------------------
message(STATUS "Build type    : ${CMAKE_BUILD_TYPE}")
message(STATUS "OpenSSL found : ${OPENSSL_VERSION}")
message(STATUS "Compiler      : ${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION}")
