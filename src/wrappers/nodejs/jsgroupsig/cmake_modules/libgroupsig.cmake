include(ExternalProject)
set(EXTERNAL_INSTALL_LOCATION ${CMAKE_BINARY_DIR}/external)

ExternalProject_Add(libgroupsig
  GIT_REPOSITORY https://github.com/IBM/libgroupsig.git
  GIT_TAG origin/master
  CMAKE_ARGS
  -DCMAKE_INSTALL_PREFIX=${EXTERNAL_INSTALL_LOCATION}
  -DCMAKE_INSTALL_RPATH=${CMAKE_BINARY_DIR}/libgroupsig-prefix/src/libgroupsig-build/external/lib
  -DUSE_MCL=ON)
