include_directories (${PROJECT_SOURCE_DIR}
                     "${PROJECT_SOURCE_DIR}/include"
                     "${PROJECT_SOURCE_DIR}/global")

add_library (dl21
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
		proof.c proof.h
		identity.c identity.h)

target_include_directories (dl21 
				PRIVATE ${GMP_INCLUDE_DIR}
				PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries (dl21
			PRIVATE ${GMP_LIBRARY}
			PRIVATE ${OPENSSL_LIBRARIES})
