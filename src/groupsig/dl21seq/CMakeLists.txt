include_directories ("${PROJECT_SOURCE_DIR}/src/include"
                     "${PROJECT_SOURCE_DIR}/src")

add_library (dl21seq
		grp_key.c grp_key.h 
		mgr_key.c mgr_key.h 
		mem_key.c mem_key.h
		signature.c signature.h
		setup.c
		join_mem.c 
		join_mgr.c 
		sign.c 
		verify.c
		identify.c
		link.c
		verify_link.c
		seqlink.c
		verify_seqlink.c
		proof.c proof.h
		identity.c identity.h)

target_include_directories (dl21seq PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries (dl21seq ${OPENSSL_LIBRARIES})
