include_directories ("${PROJECT_SOURCE_DIR}/src/include"
                     "${PROJECT_SOURCE_DIR}/src")

add_library (ps16 
  grp_key.c grp_key.h 
  mgr_key.c mgr_key.h 
  mem_key.c mem_key.h 
  signature.c signature.h 
  setup.c 
  join_mem.c join_mgr.c 
  sign.c 
  verify.c 
  open.c
  open_verify.c
  gml.c gml.h
  proof.c proof.h)

target_include_directories (ps16 PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries (ps16 PRIVATE ${OPENSSL_LIBRARIES})
