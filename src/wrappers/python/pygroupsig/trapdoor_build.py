# file "trapdoor_build.py"

from pygroupsig.common_build import ffibuilder

ffibuilder.cdef("""
typedef struct {
uint8_t scheme;
void *trap;
} trapdoor_t;
""")

ffibuilder.cdef("""
typedef trapdoor_t* (*trapdoor_init_f)(void);
""")

ffibuilder.cdef("""
typedef int (*trapdoor_free_f)(trapdoor_t *trap);
""")

ffibuilder.cdef("""
typedef int (*trapdoor_copy_f)(trapdoor_t *dst, trapdoor_t *src);
""")

ffibuilder.cdef("""
typedef char* (*trapdoor_to_string_f)(trapdoor_t *trap);
""")

ffibuilder.cdef("""
typedef trapdoor_t* (*trapdoor_from_string_f)(char *strap);
""")

ffibuilder.cdef("""
typedef struct {
uint8_t scheme;
trapdoor_init_f init;
trapdoor_free_f free;
trapdoor_copy_f copy;
trapdoor_to_string_f to_string;
trapdoor_from_string_f from_string;
} trapdoor_handle_t;
""")

ffibuilder.cdef("""
const trapdoor_handle_t* trapdoor_handle_from_code(uint8_t code);
""")

ffibuilder.cdef("""
trapdoor_t* trapdoor_init(uint8_t code);
""")

ffibuilder.cdef("""
int trapdoor_free(trapdoor_t *trap);
""")

ffibuilder.cdef("""
int trapdoor_copy(trapdoor_t *dst, trapdoor_t *src);
""")

ffibuilder.cdef("""
char* trapdoor_to_string(trapdoor_t *trap);
""")

ffibuilder.cdef("""
trapdoor_t *trapdoor_from_string(uint8_t code, char *strap);
""")
