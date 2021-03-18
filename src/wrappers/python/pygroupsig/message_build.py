# file "message_build.py"

from pygroupsig.common_build import ffibuilder
import pygroupsig.types_build

ffibuilder.cdef("""                
typedef struct _message_t {
byte_t *bytes;
uint64_t length;
} message_t;
""")

ffibuilder.cdef("""
message_t* message_init(void);
""")

ffibuilder.cdef("""
message_t* message_from_string(char *str);
""")

ffibuilder.cdef("""
message_t* message_from_bytes(byte_t *bytes, uint64_t length);
""")

ffibuilder.cdef("""
int message_free(message_t *msg);
""")

ffibuilder.cdef("""                
int message_set_bytes(message_t *msg, byte_t *bytes, uint64_t length);
""")

ffibuilder.cdef("""
int message_set_bytes_from_string(message_t *msg, char *string);
""")

ffibuilder.cdef("""                
int message_copy(message_t *dst, message_t *src);
""")

ffibuilder.cdef("""
char* message_to_string(message_t *msg);
""")

ffibuilder.cdef("""
char* message_to_base64(message_t *msg);
""")

ffibuilder.cdef("""
message_t* message_from_base64(char *str);
""")
