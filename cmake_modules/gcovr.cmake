include(ExternalProject)
ExternalProject_Add(gcovr
  #URL https://github.com/gcovr/gcovr/archive/3.2.zip
  #URL_HASH SHA1=7411d3989116c5fa65519ee1a54237df16944ad2
  URL https://github.com/gcovr/gcovr/archive/4.2.zip
  URL_HASH SHA1=f8f33794d7e09a4009e3623009b3769a726b1908
  CONFIGURE_COMMAND ""
  BUILD_COMMAND ""
  INSTALL_COMMAND ""
  )

ExternalProject_Get_Property(gcovr source_dir)
SET(GCOVR gcovr)

SET(GCC_COVERAGE_COMPILE_FLAGS "-g -O0 -fprofile-arcs -ftest-coverage")
SET(GCC_COVERAGE_LINK_FLAGS "-lgcov")
SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${GCC_COVERAGE_COMPILE_FLAGS}" )
SET(CMAKE_EXE_LINKER_FLAGS "${CMAKE_LINKER_FLAGS} ${GCC_COVERAGE_LINK_FLAGS}" )

add_custom_command(OUTPUT _run_gcovr_parser
  POST_BUILD
  COMMAND python -m ${GCOVR} -r ${CMAKE_SOURCE_DIR} --xml -o ${CMAKE_BINARY_DIR}/coverage.xml --object-dir=${CMAKE_BINARY_DIR} -e test_* --exclude-directories=gtest*,src/wrappers
#  COMMAND python -m ${GCOVR} -r ${CMAKE_SOURCE_DIR} --html --html-details -o ${CMAKE_BINARY_DIR}/coverage.html --object-dir=${CMAKE_BINARY_DIR} -e test_* --exclude-directories=gtest*
  WORKING_DIRECTORY ${source_dir})
add_custom_target (coverage DEPENDS _run_gcovr_parser)
