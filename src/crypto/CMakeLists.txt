# libgcrypto
add_library (gcrypto spk.c prf.c)
target_link_libraries (gcrypto PRIVATE ${OPENSSL_LIBRARIES})
