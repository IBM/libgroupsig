cmake_minimum_required(VERSION 3.13)
project (jsgroupsig)

# Add modules
list (APPEND CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake_modules)

# Install libgroupsig
include(libgroupsig)

include_directories(
  build/external/include/groupsig)

link_directories(
  build/external/lib
  build/libgroupsig-prefix/src/libgroupsig-build/external/lib)

file(GLOB SOURCE_C_FILES "src/*")
#file(GLOB SOURCE_JS_FILES "lib/*")

add_library(${PROJECT_NAME}
  SHARED
  ${SOURCE_C_FILES}
  ${SOURCE_JS_FILES})

add_dependencies(${PROJECT_NAME} libgroupsig)

set_target_properties(${PROJECT_NAME}
  PROPERTIES PREFIX "" SUFFIX ".node")
target_include_directories(${PROJECT_NAME}
  PRIVATE
  "${CMAKE_SOURCE_DIR}/node_modules/node-addon-api")
target_link_libraries(${PROJECT_NAME}
  PUBLIC
  groupsig)

#target_link_libraries(${PROJECT_NAME} ${CMAKE_JS_LIB})
