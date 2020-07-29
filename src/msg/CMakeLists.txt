# libmsg
add_library (msg misc.c misc.h message.c)
target_link_libraries (msg base64)
