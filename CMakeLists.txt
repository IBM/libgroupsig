# CMake requirements
cmake_minimum_required (VERSION 3.13)
set (CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}")

# Generic library information
project (libgroupsig)
set (libgroupsig_VERSION_MAJOR 0)
set (libgroupsig_VERSION_MINOR 1)
set (libgroupsig_VERSION_PATCH 0)

# Set the paths for produced libraries and runtime binaries
set (CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set (CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set (CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set (CMAKE_INSTALL_RPATH "${CMAKE_INSTALL_PREFIX}/lib")

# Global compiler flags
set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIC")
set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIC")

# Add the binary tree to the search path for include files
include_directories("${CMAKE_SOURCE_DIR}/src")
include_directories("${CMAKE_SOURCE_DIR}/src/include")
include_directories("${CMAKE_BINARY_DIR}/external/include")
link_directories("${CMAKE_BINARY_DIR}/external/lib")

# Check dependencies

## OpenSSL
find_package (OpenSSL REQUIRED)

# Add modules
list (APPEND CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake_modules)

## Configure options
option (
  USE_GTEST
  "Build with GoogleTest for testing.")

option (
  USE_GCOV
  "Build with GCov for coverage reporting.")

option (
  USE_MCL
  "Build a local version of MCL for pairing based crypto."
  ON)

## Google Test
if (USE_GTEST)
  #  SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O0 -fprofile-arcs -ftest-coverage")
  #  SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${GCC_TEST_COMPILE_FLAGS}" )
  include (gtest)
endif (USE_GTEST)

## GCOV
if (USE_GCOV)
  include (gcovr)
endif (USE_GCOV)

## MCL
if (USE_MCL)
  include (mcl)
#  link_directories("${CMAKE_BINARY_DIR}/external/kk/lib")
else ()
  find_package (MCL REQUIRED)
  include_directories(${MCL_INCLUDE_DIRS})
endif (USE_MCL)

## @TODO Is this needed/used?
## CTest
include (CTest)

# Subdirectories
add_subdirectory (${CMAKE_SOURCE_DIR}/src/logger)
add_subdirectory (${CMAKE_SOURCE_DIR}/src/msg)
add_subdirectory (${CMAKE_SOURCE_DIR}/src/sys)
add_subdirectory (${CMAKE_SOURCE_DIR}/src/shim)
add_subdirectory (${CMAKE_SOURCE_DIR}/src/crypto)
add_subdirectory (${CMAKE_SOURCE_DIR}/src/math)
add_subdirectory (${CMAKE_SOURCE_DIR}/src/misc)
add_subdirectory (${CMAKE_SOURCE_DIR}/src/groupsig)
add_subdirectory (${PROJECT_SOURCE_DIR}/src/tools)
