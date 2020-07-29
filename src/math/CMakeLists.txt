# libmath
add_library (math nt.c rnd.c perm.c nt.h rnd.h perm.h)
target_link_libraries (math big m)
