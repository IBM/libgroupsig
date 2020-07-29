include_directories ("${PROJECT_SOURCE_DIR}/src/include"
                     "${PROJECT_SOURCE_DIR}/src/global")

add_library (libkty04 grp_key.c grp_key.h mgr_key.c mgr_key.h mem_key.c
        mem_key.h signature.c signature.h sphere.c sphere.h setup.c
        join_mem.c join_mgr.c sign.c verify.c open.c reveal.c trace.c claim.c
        claim_verify.c prove_equality.c prove_equality_verify.c gml.c gml.h
        crl.c crl.h proof.c proof.h identity.c identity.h trapdoor.c trapdoor.h)

target_include_directories (libkty04 PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries (libkty04 PRIVATE ${OPENSSL_LIBRARIES})
