find_package(PkgConfig)
set(MCL_PREFIX "${CMAKE_BINARY_DIR}/mcl" CACHE PATH "path ")

message(${MCL_PREFIX})

find_path(MCL_INCLUDE_DIR
  NAMES bn.h
  PATHS ${MCL_PREFIX})#/include/mcl /usr/include/mcl /usr/local/include/mcl)

find_library(MCL_LIBRARY
  NAMES mcl # mcl mclbn384_256 #libmcl #libmclbn384_256 
  PATHS ${MCL_PREFIX}/lib)# /usr/lib /usr/local/lib)

find_library(MCL384_256_LIBRARY
  NAMES mclbn384_256
  PATHS ${MCL_PREFIX}/lib)# /usr/lib /usr/local/lib)

if(MCL_INCLUDE_DIR AND MCL_LIBRARY)
  get_filename_component(MCL_LIBRARY_DIR ${MCL_LIBRARY} PATH)
  set(MCL_FOUND TRUE)
endif()

if(MCL_FOUND)
  set(MCL_INCLUDE_DIRS ${MCL_INCLUDE_DIR})
  if(NOT MCL_FIND_QUIETLY)
    MESSAGE(STATUS "Found MCL: ${MCL_LIBRARY}")
  endif()
elseif(MCL_FOUND)
  if(MCL_FIND_REQUIRED)
    message(FATAL_ERROR "Could not find MCL")
  endif()
endif()
