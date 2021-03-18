include_directories ("${PROJECT_SOURCE_DIR}/src/include"
  "${PROJECT_SOURCE_DIR}/src")

add_library (gl19
  grp_key.c grp_key.h 
  mgr_key.c mgr_key.h 
  mem_key.c mem_key.h
  bld_key.c bld_key.h
  signature.c signature.h
  blindsig.c blindsig.h
  setup.c
  join_mem.c 
  join_mgr.c 
  sign.c 
  verify.c 
  blind.c
  convert.c
  unblind.c
  identity.c identity.h)

target_include_directories (gl19 PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries (gl19 PRIVATE ${OPENSSL_LIBRARIES})
