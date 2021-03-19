set(src
  groupsig.c
  grp_key.c
  mgr_key.c
  mem_key.c
  bld_key.c
  signature.c
  blindsig.c
  proof.c
  identity.c
  trapdoor.c
  gml.c
  crl.c)

# this is the "object library" target: compiles the sources only once
add_library(objlib OBJECT ${src})

# shared libraries need PIC
set_property(TARGET objlib PROPERTY POSITION_INDEPENDENT_CODE 1)

# shared and static libraries built from the same object files
add_library(groupsig SHARED $<TARGET_OBJECTS:objlib>)
add_library(groupsig-static STATIC $<TARGET_OBJECTS:objlib>)

target_link_libraries (groupsig 
  #PUBLIC kty04 
  PUBLIC bbs04 
  #PUBLIC cpy06
  PUBLIC gl19
  PUBLIC ps16
  PUBLIC klap20
  PUBLIC dl21
  PUBLIC dl21seq  
  PUBLIC sys 
  PUBLIC math
  PUBLIC base64 
  PUBLIC misc
  PUBLIC hash
  PUBLIC gcrypto
  PUBLIC msg 
  PUBLIC pbcext
  PUBLIC logger
  PUBLIC ${OPENSSL_LIBRARIES} 
  PUBLIC ${MCL_LIBRARY}
  PUBLIC ${MCL384_256_LIBRARY})

# Install rules
install (TARGETS groupsig DESTINATION lib)
install (DIRECTORY "${PROJECT_SOURCE_DIR}/src/include/"
  DESTINATION "include/groupsig"
  FILES_MATCHING PATTERN "*.h")

# Ignore kty04 and cpy06 until I adapt them to the new pbc and join
add_subdirectory(bbs04)
#add_subdirectory(kty04)
#add_subdirectory(cpy06)
add_subdirectory(gl19)
add_subdirectory(ps16)
add_subdirectory(klap20)
add_subdirectory(dl21)
add_subdirectory(dl21seq)
