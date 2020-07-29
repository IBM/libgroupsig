# file "identity_build.py"

from pygroupsig.common_build import ffibuilder

ffibuilder.cdef("""
typedef struct {
uint8_t scheme;
void *id;
} identity_t;
""")

ffibuilder.cdef("""
typedef identity_t* (*identity_init_f)(void);
""")

ffibuilder.cdef("""
typedef int (*identity_free_f)(identity_t *id);
""")

ffibuilder.cdef("""
typedef int (*identity_copy_f)(identity_t *dst, identity_t *src);
""")

ffibuilder.cdef("""
typedef uint8_t (*identity_cmp_f)(identity_t *id1, identity_t *id2);
""")

ffibuilder.cdef("""
typedef char* (*identity_to_string_f)(identity_t *id);
""")

ffibuilder.cdef("""
typedef identity_t* (*identity_from_string_f)(char *sid);
""")

ffibuilder.cdef("""
typedef struct {
uint8_t scheme;
identity_init_f init;
identity_free_f free;
identity_copy_f copy;
identity_cmp_f cmp;
identity_to_string_f to_string;
identity_from_string_f from_string;
} identity_handle_t;
""")

ffibuilder.cdef("""
const identity_handle_t* identity_handle_from_code(uint8_t code);
""")

ffibuilder.cdef("""
identity_t* identity_init(uint8_t code);
""")

ffibuilder.cdef("""
int identity_free(identity_t *id);
""")

ffibuilder.cdef("""
int identity_copy(identity_t *dst, identity_t *src);
""")

ffibuilder.cdef("""
uint8_t identity_cmp(identity_t *id1, identity_t *id2);
""")

ffibuilder.cdef("""
char* identity_to_string(identity_t *id);
""")

ffibuilder.cdef("""
identity_t *identity_from_string(uint8_t code, char *sid);
""")
